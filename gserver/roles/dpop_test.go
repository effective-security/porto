package roles_test

import (
	"crypto"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

const (
	dpopRPCMethod    = "/porto.test.Echo/Echo"
	dpopRPCAuthority = "api.example:8443"
	dpopRPCURI       = "https://" + dpopRPCAuthority + dpopRPCMethod
)

func TestGRPCDPoPBinding(t *testing.T) {
	t.Parallel()
	key, err := dpop.GenerateKey("")
	require.NoError(t, err)
	signer, err := dpop.NewSigner(key.Key.(crypto.Signer))
	require.NoError(t, err)
	issuer, err := jwt.NewProviderFromCryptoSigner(key.Key.(crypto.Signer))
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		authority []string
		proofURI  string
		proofHTM  string
		wrongKey  bool
		wantErr   string
	}{
		{
			name:      "authority_and_method",
			authority: []string{dpopRPCAuthority},
			proofURI:  dpopRPCURI,
		},
		{
			name:      "default_port_and_host_case",
			authority: []string{"API.EXAMPLE:443"},
			proofURI:  "https://api.example" + dpopRPCMethod,
		},
		{
			name:      "ipv6",
			authority: []string{"[::1]:8443"},
			proofURI:  "https://[::1]:8443" + dpopRPCMethod,
		},
		{
			// grpc-go escapes the zone in :authority and in the audience
			name:      "ipv6_zone",
			authority: []string{"[fe80::1%25eth0]:8443"},
			proofURI:  "https://[fe80::1%25eth0]:8443" + dpopRPCMethod,
		},
		{
			name:     "missing_authority",
			proofURI: dpopRPCURI,
			wantErr:  "dpop: exactly one non-empty :authority is required",
		},
		{
			name:      "empty_authority",
			authority: []string{""},
			proofURI:  dpopRPCURI,
			wantErr:   "dpop: exactly one non-empty :authority is required",
		},
		{
			name:      "duplicate_authority",
			authority: []string{dpopRPCAuthority, dpopRPCAuthority},
			proofURI:  dpopRPCURI,
			wantErr:   "dpop: exactly one non-empty :authority is required",
		},
		{
			name:      "malformed_authority",
			authority: []string{"api.example:bad"},
			proofURI:  dpopRPCURI,
			wantErr:   "dpop: invalid :authority",
		},
		{
			// a proof for /x/porto.test.Echo/Echo must not match the method
			name:      "authority_with_path",
			authority: []string{"api.example:8443/x"},
			proofURI:  "https://api.example:8443/x" + dpopRPCMethod,
			wantErr:   "dpop: :authority must be host[:port]",
		},
		{
			name:      "authority_with_userinfo",
			authority: []string{"alice@" + dpopRPCAuthority},
			proofURI:  dpopRPCURI,
			wantErr:   "dpop: :authority must be host[:port]",
		},
		{
			name:      "authority_with_query",
			authority: []string{dpopRPCAuthority + "?"},
			proofURI:  dpopRPCURI,
			wantErr:   "dpop: :authority must be host[:port]",
		},
		{
			name:      "authority_with_fragment",
			authority: []string{dpopRPCAuthority + "#"},
			proofURI:  dpopRPCURI,
			wantErr:   "dpop: :authority must be host[:port]",
		},
		{
			name:      "hostless_authority",
			authority: []string{":"},
			proofURI:  "https://:" + dpopRPCMethod,
			wantErr:   "dpop: authority must contain a hostname",
		},
		{
			name:      "port_only_authority",
			authority: []string{":443"},
			proofURI:  "https://:443" + dpopRPCMethod,
			wantErr:   "dpop: authority must contain a hostname",
		},
		{
			name:      "wrong_authority",
			authority: []string{"other.example:8443"},
			proofURI:  dpopRPCURI,
			wantErr:   "dpop: claim mismatch: http_uri",
		},
		{
			name:      "wrong_port",
			authority: []string{"api.example:8444"},
			proofURI:  dpopRPCURI,
			wantErr:   "dpop: claim mismatch: http_uri",
		},
		{
			name:      "wrong_method_path",
			authority: []string{dpopRPCAuthority},
			proofURI:  "https://" + dpopRPCAuthority + "/porto.test.Echo/Watch",
			wantErr:   "dpop: claim mismatch: http_uri",
		},
		{
			name:      "method_path_case",
			authority: []string{dpopRPCAuthority},
			proofURI:  "https://" + dpopRPCAuthority + "/porto.test.Echo/echo",
			wantErr:   "dpop: claim mismatch: http_uri",
		},
		{
			name:      "legacy_relative_proof",
			authority: []string{dpopRPCAuthority},
			proofURI:  dpopRPCMethod,
			wantErr:   "dpop: invalid http_uri claim",
		},
		{
			name:      "http_scheme",
			authority: []string{dpopRPCAuthority},
			proofURI:  "http://" + dpopRPCAuthority + dpopRPCMethod,
			wantErr:   "dpop: claim mismatch: http_uri",
		},
		{
			name:      "wrong_http_method",
			authority: []string{dpopRPCAuthority},
			proofURI:  dpopRPCURI,
			proofHTM:  http.MethodGet,
			wantErr:   "dpop: claim mismatch: http_method",
		},
		{
			name:      "wrong_key_binding",
			authority: []string{dpopRPCAuthority},
			proofURI:  dpopRPCURI,
			wrongKey:  true,
			wantErr:   "dpop: thumbprint mismatch",
		},
	} {
		for _, strict := range []bool{false, true} {
			name := tc.name + "/fallback"
			if strict {
				name = tc.name + "/strict"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				p, err := roles.New(&roles.IdentityMap{
					Strict: strict,
					DPoP: roles.JWTIdentityMap{
						Enabled:                  true,
						DefaultAuthenticatedRole: roles.DPoPUserRoleName,
					},
				}, issuer)
				require.NoError(t, err)
				jkt := signer.JWKThumbprint()
				if tc.wrongKey {
					jkt = "another-key-thumbprint"
				}
				token, err := issuer.Sign(t.Context(), jwt.MapClaims{
					"sub": "alice",
					"exp": time.Now().Add(time.Hour),
					"cnf": map[string]any{"jkt": jkt},
				})
				require.NoError(t, err)
				u, err := url.Parse(tc.proofURI)
				require.NoError(t, err)
				method := tc.proofHTM
				if method == "" {
					method = http.MethodPost
				}
				proof, err := signer.Sign(t.Context(), method, u, nil)
				require.NoError(t, err)
				md := metadata.Pairs(header.Authorization, "DPoP "+token, header.DPoP, proof)
				if tc.authority != nil {
					md.Set(header.Authority, tc.authority...)
				}
				ctx := metadata.NewIncomingContext(t.Context(), md)
				id, err := p.IdentityFromContext(ctx, dpopRPCMethod)
				if tc.wantErr != "" && strict {
					require.ErrorContains(t, err, tc.wantErr)
					assert.Nil(t, id)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, id)
				if tc.wantErr != "" {
					assert.Equal(t, roles.GuestRoleName, id.Role())
					return
				}
				assert.Equal(t, roles.DPoPUserRoleName, id.Role())
				assert.Equal(t, identity.MethodDPoP, id.AuthMethod())
				assert.Equal(t, "alice", id.Subject())
			})
		}
	}
}
