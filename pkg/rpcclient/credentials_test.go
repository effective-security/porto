package rpcclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/pkg/rpcclient"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xpki/jwt/dpop"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	authorizationMD = "authorization"
	dpopMD          = "dpop"
	userAgentMD     = "user-agent"
)

// staticIdentity is a credentials.CallerIdentity that returns a fixed token.
type staticIdentity struct {
	token credentials.Token
}

func (s staticIdentity) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	tok := s.token
	return &tok, nil
}

func TestNewSendsAuthorization(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(time.Hour)
	tcs := []struct {
		name           string
		callerIdentity credentials.CallerIdentity
		authToken      *retriable.AuthToken
		exp            string
	}{
		{
			name: "caller identity",
			callerIdentity: staticIdentity{token: credentials.Token{
				TokenType:   "Bearer",
				AccessToken: "from-provider",
				Expires:     &future,
			}},
			exp: "Bearer from-provider",
		},
		{
			name: "caller identity takes precedence over auth token",
			callerIdentity: staticIdentity{token: credentials.Token{
				TokenType:   "Bearer",
				AccessToken: "from-provider",
			}},
			authToken: &retriable.AuthToken{AccessToken: "static"},
			exp:       "Bearer from-provider",
		},
		{
			name:      "auth token defaults to Bearer",
			authToken: &retriable.AuthToken{AccessToken: "static"},
			exp:       "Bearer static",
		},
		{
			name: "auth token keeps its type and unexpired expiry",
			authToken: &retriable.AuthToken{
				AccessToken: "static",
				TokenType:   "Custom",
				Expires:     &future,
			},
			exp: "Custom static",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startTestServer(t, true)
			client, err := rpcclient.New(&rpcclient.Config{
				Endpoint:       srv.endpoint,
				TLS:            srv.clientTLS,
				CallerIdentity: tc.callerIdentity,
				AuthToken:      tc.authToken,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			_, err = healthCheck(t.Context(), client.Conn(), "", client.Opts()...)
			require.NoError(t, err)

			md := srv.lastMD()
			assert.Equal(t, []string{tc.exp}, md.Get(authorizationMD))
			assert.Empty(t, md.Get(dpopMD))
		})
	}
}

func TestNewWithoutTLSSendsNoAuthorization(t *testing.T) {
	t.Parallel()

	srv := startTestServer(t, false)
	// New installs AuthToken and CallerIdentity only with TLS, so a
	// plaintext client sends no authorization metadata
	client, err := rpcclient.New(&rpcclient.Config{
		Endpoint:  srv.endpoint,
		AuthToken: &retriable.AuthToken{AccessToken: "static"},
		UserAgent: "porto-rpcclient-test/1.0",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = healthCheck(t.Context(), client.Conn(), "", client.Opts()...)
	require.NoError(t, err)

	md := srv.lastMD()
	assert.Empty(t, md.Get(authorizationMD))
	ua := md.Get(userAgentMD)
	require.Len(t, ua, 1)
	// grpc-go appends its own product token to the configured user agent
	assert.Regexp(t, `^porto-rpcclient-test/1\.0 grpc-go/`, ua[0])
}

func TestNewSignsDPoPProofWithStoredKey(t *testing.T) {
	t.Parallel()

	key, err := dpop.GenerateKey("")
	require.NoError(t, err)
	jkt, err := dpop.Thumbprint(key)
	require.NoError(t, err)

	folder := t.TempDir()
	_, err = retriable.NewStorage(folder).SaveKey(key)
	require.NoError(t, err)

	srv := startTestServer(t, true)
	client, err := rpcclient.New(&rpcclient.Config{
		Endpoint:      srv.endpoint,
		TLS:           srv.clientTLS,
		StorageFolder: folder,
		AuthToken: &retriable.AuthToken{
			AccessToken: "bound-token",
			// a token bound to a DPoP key is always sent as DPoP
			TokenType: "Bearer",
			DpopJkt:   jkt,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	expectedURI := "https://" + srv.clientTLS.ServerName + healthCheckMethod
	jtis := map[string]bool{}
	for range 2 {
		_, err = healthCheck(t.Context(), client.Conn(), "", client.Opts()...)
		require.NoError(t, err)

		md := srv.lastMD()
		assert.Equal(t, []string{srv.clientTLS.ServerName}, md.Get(header.Authority))
		assert.Equal(t, []string{"DPoP bound-token"}, md.Get(authorizationMD))
		proofs := md.Get(dpopMD)
		require.Len(t, proofs, 1)

		claims := verifyProof(t, proofs[0], jkt)
		assert.Equal(t, http.MethodPost, claims.Method)
		assert.Equal(t, expectedURI, claims.URI)
		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, proofs[0], http.MethodPost, expectedURI)
		require.NoError(t, err)
		require.NotEmpty(t, claims.ID)
		assert.False(t, jtis[claims.ID], "proof reused for a second RPC")
		jtis[claims.ID] = true
	}
}

// proofClaims are the DPoP proof claims checked by the tests.
type proofClaims struct {
	Method string `json:"htm"`
	URI    string `json:"htu"`
	ID     string `json:"jti"`
}

// verifyProof checks that proof is a DPoP JWT signed by the key whose
// thumbprint is jkt and returns its claims.
func verifyProof(t *testing.T, proof, jkt string) proofClaims {
	t.Helper()

	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	require.Len(t, jws.Signatures, 1)
	hdr := jws.Signatures[0].Protected
	assert.Equal(t, "dpop+jwt", hdr.ExtraHeaders[jose.HeaderType])
	require.NotNil(t, hdr.JSONWebKey)
	assert.True(t, hdr.JSONWebKey.IsPublic())
	thumbprint, err := dpop.Thumbprint(hdr.JSONWebKey)
	require.NoError(t, err)
	assert.Equal(t, jkt, thumbprint)

	payload, err := jws.Verify(hdr.JSONWebKey)
	require.NoError(t, err)
	var claims proofClaims
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func TestNewRejectsAuthToken(t *testing.T) {
	t.Parallel()

	key, err := dpop.GenerateKey("")
	require.NoError(t, err)
	jkt, err := dpop.Thumbprint(key)
	require.NoError(t, err)

	// an Ed25519 key loads as a JWK but cannot sign DPoP proofs
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edKey := &jose.JSONWebKey{Key: edPriv}
	edJkt, err := dpop.Thumbprint(edKey)
	require.NoError(t, err)

	folder := t.TempDir()
	storage := retriable.NewStorage(folder)
	_, err = storage.SaveKey(edKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(folder, "malformed.jwk"), []byte("{"), 0o600))

	past := time.Now().Add(-time.Minute)
	tcs := []struct {
		name      string
		authToken *retriable.AuthToken
		expErr    string
		expIs     error
	}{
		{
			name:      "expired",
			authToken: &retriable.AuthToken{AccessToken: "old", Expires: &past},
			expErr:    "authorization: token expired",
		},
		{
			name:      "missing DPoP key",
			authToken: &retriable.AuthToken{AccessToken: "bound", DpopJkt: jkt},
			expErr:    "unable to load key for DPoP: open " + filepath.Join(folder, jkt+".jwk") + ": no such file or directory",
			expIs:     fs.ErrNotExist,
		},
		{
			name:      "malformed DPoP key",
			authToken: &retriable.AuthToken{AccessToken: "bound", DpopJkt: "malformed"},
			expErr:    "unable to load key for DPoP: unexpected end of JSON input",
		},
		{
			name:      "unsupported DPoP key",
			authToken: &retriable.AuthToken{AccessToken: "bound", DpopJkt: edJkt},
			expErr:    "unable to create DPoP signer: public key not supported: ed25519.PublicKey",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &rpcclient.Config{
				Endpoint:  "https://127.0.0.1:1",
				TLS:       &tls.Config{MinVersion: tls.VersionTLS12},
				AuthToken: tc.authToken,
			}
			cfg.SetStorage(storage)

			client, err := rpcclient.New(cfg)
			require.Nil(t, client)
			require.EqualError(t, err, tc.expErr)
			if tc.expIs != nil {
				assert.ErrorIs(t, err, tc.expIs)
			}
		})
	}
}
