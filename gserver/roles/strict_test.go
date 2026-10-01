package roles_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"testing"

	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

const (
	testAuthCookie = "auth_token"
	testCSRFCookie = "csrf_token"
	// testProof is not a valid DPoP proof
	testProof = "not-a-dpop-proof"
)

var errTestToken = errors.New("token is not valid")

func TestNewRequiresJWTParser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     roles.IdentityMap
		wantErr string
	}{
		{
			name:    "dpop",
			cfg:     roles.IdentityMap{DPoP: roles.JWTIdentityMap{Enabled: true}},
			wantErr: "dpop: JWT parser is required",
		},
		{
			name:    "jwt",
			cfg:     roles.IdentityMap{JWT: roles.JWTIdentityMap{Enabled: true}},
			wantErr: "jwt: JWT parser is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := roles.New(&tt.cfg, nil)
			require.EqualError(t, err, tt.wantErr)
			assert.Nil(t, p)
		})
	}
}

func TestGetCookiesConfig(t *testing.T) {
	t.Parallel()
	var empty *roles.IdentityMap
	assert.Equal(t, roles.CookiesConfig{}, empty.GetCookiesConfig())

	cookies := roles.CookiesConfig{
		Auth:   testAuthCookie,
		CSRF:   testCSRFCookie,
		Domain: "example.com",
	}
	assert.Equal(t, cookies, (&roles.IdentityMap{Cookies: cookies}).GetCookiesConfig())
}

// TestApplicableWithJWT checks that a provider with JWT applies to
// requests that carry a token in the Authorization header or metadata, or
// a non-empty auth cookie, and to no other request.
func TestApplicableWithJWT(t *testing.T) {
	t.Parallel()
	p, err := roles.New(&roles.IdentityMap{
		Cookies: roles.CookiesConfig{
			Auth: testAuthCookie,
			CSRF: testCSRFCookie,
		},
		JWT: roles.JWTIdentityMap{Enabled: true},
	}, mockJWT{})
	require.NoError(t, err)

	for _, tt := range []struct {
		name   string
		header http.Header
		want   bool
	}{
		{"authorization", http.Header{header.Authorization: {"Bearer token"}}, true},
		{"auth cookie", http.Header{header.Cookie: {testAuthCookie + "=token"}}, true},
		{"empty auth cookie", http.Header{header.Cookie: {testAuthCookie + "="}}, false},
		{"other cookie", http.Header{header.Cookie: {testCSRFCookie + "=token"}}, false},
		{"no credentials", http.Header{}, false},
	} {
		r, err := http.NewRequest(http.MethodGet, "/", nil)
		require.NoError(t, err)
		r.Header = tt.header
		assert.Equal(t, tt.want, p.ApplicableForRequest(r), "HTTP %s", tt.name)

		md := metadata.MD{}
		for k, v := range tt.header {
			md.Append(k, v...)
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)
		assert.Equal(t, tt.want, p.ApplicableForContext(ctx), "gRPC %s", tt.name)
	}
}

// TestSkipAuthPaths checks that SkipAuthPaths returns the guest identity
// without checking credentials, even in Strict mode, and only on HTTP.
func TestSkipAuthPaths(t *testing.T) {
	t.Parallel()
	p, err := roles.New(&roles.IdentityMap{
		Strict:        true,
		SkipAuthPaths: []string{"/healthz"},
		JWT:           roles.JWTIdentityMap{Enabled: true},
	}, mockJWT{err: errTestToken})
	require.NoError(t, err)

	r, err := http.NewRequest(http.MethodGet, "/healthz", nil)
	require.NoError(t, err)
	setAuthorizationHeader(r, "AccessToken123")
	id, err := p.IdentityFromRequest(r)
	require.NoError(t, err)
	assert.Equal(t, roles.GuestRoleName, id.Role())

	r, err = http.NewRequest(http.MethodGet, "/v1/items", nil)
	require.NoError(t, err)
	setAuthorizationHeader(r, "AccessToken123")
	_, err = p.IdentityFromRequest(r)
	require.ErrorIs(t, err, errTestToken)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer AccessToken123"))
	_, err = p.IdentityFromContext(ctx, "/healthz")
	require.ErrorIs(t, err, errTestToken)
}

// TestStrictRejectsInvalidCredentials checks that a DPoP proof or a client
// certificate that fails verification fails the request in Strict mode and
// falls back to the guest identity otherwise, on HTTP and gRPC.
func TestStrictRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()
	// a certificate without a SPIFFE URI has no identity
	noSPIFFE := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "client"}},
		},
	}
	tests := []struct {
		name    string
		cfg     roles.IdentityMap
		request func(*http.Request)
		md      metadata.MD
		peer    *tls.ConnectionState
		wantErr string
	}{
		{
			name: "dpop",
			cfg: roles.IdentityMap{
				DPoP: roles.JWTIdentityMap{Enabled: true},
			},
			request: func(r *http.Request) {
				setAuthorizationDPoPHeader(r, testProof, "AccessToken123")
			},
			md:      metadata.Pairs("authorization", "DPoP AccessToken123", "dpop", testProof, header.Authority, "api.test"),
			wantErr: "dpop: failed to parse header",
		},
		{
			name: "tls",
			cfg: roles.IdentityMap{
				TLS: roles.GenericIdentityMap{Enabled: true},
			},
			request: func(r *http.Request) {
				r.TLS = noSPIFFE
			},
			peer:    noSPIFFE,
			wantErr: `could not determine identity: "client"`,
		},
	}
	for _, tt := range tests {
		for _, strict := range []bool{false, true} {
			cfg := tt.cfg
			cfg.Strict = strict
			cfg.DebugLogs = true
			p, err := roles.New(&cfg, mockJWT{})
			require.NoError(t, err)

			r, err := http.NewRequest(http.MethodPost, "https://api.test/v1/items", nil)
			require.NoError(t, err)
			tt.request(r)
			id, err := p.IdentityFromRequest(r)
			checkStrict(t, strict, tt.wantErr, id, err, "HTTP "+tt.name)

			ctx := metadata.NewIncomingContext(context.Background(), tt.md)
			if tt.peer != nil {
				ctx = createPeerContext(ctx, tt.peer)
			}
			id, err = p.IdentityFromContext(ctx, "/v1/items")
			checkStrict(t, strict, tt.wantErr, id, err, "gRPC "+tt.name)
		}
	}
}

func checkStrict(t *testing.T, strict bool, wantErr string, id identity.Identity, err error, msg string) {
	t.Helper()
	if strict {
		require.Error(t, err, msg)
		assert.Contains(t, err.Error(), wantErr, msg)
		assert.Nil(t, id, msg)
		return
	}
	require.NoError(t, err, msg)
	assert.Equal(t, roles.GuestRoleName, id.Role(), msg)
}

// TestCookieAuthInvalidTokenGRPC checks that an auth cookie whose JWT fails
// verification falls back to the guest identity even in Strict mode.
func TestCookieAuthInvalidTokenGRPC(t *testing.T) {
	t.Parallel()
	p, err := roles.New(&roles.IdentityMap{
		Strict:    true,
		DebugLogs: true,
		Cookies: roles.CookiesConfig{
			Auth: testAuthCookie,
			CSRF: testCSRFCookie,
		},
		JWT: roles.JWTIdentityMap{Enabled: true},
	}, mockJWT{claims: jwt.MapClaims{"sub": "user"}, err: errTestToken})
	require.NoError(t, err)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"cookie", testAuthCookie+"=AccessToken123; "+testCSRFCookie+"=abc",
		"x-csrf-token", "abc",
	))
	id, err := p.IdentityFromContext(ctx, "/test")
	require.NoError(t, err)
	assert.Equal(t, roles.GuestRoleName, id.Role())
	assert.Equal(t, identity.MethodNone, id.AuthMethod())
}
