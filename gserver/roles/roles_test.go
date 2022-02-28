package roles_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func Test_Empty(t *testing.T) {
	p, err := roles.New(&roles.IdentityMap{}, nil)
	require.NoError(t, err)

	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	id, err := p.IdentityFromRequest(r)
	require.NoError(t, err)
	require.NotNil(t, id)
	assert.Equal(t, identity.GuestRoleName, id.Role())
}

func Test_All(t *testing.T) {
	xlog.SetGlobalLogLevel(xlog.DEBUG)

	mock := mockJWT{
		claims: jwt.MapClaims{
			"sub": "denis@trusty.com",
			"cnf": map[string]interface{}{
				dpop.CnfThumbprint: "C8kBamVR4FbaWBy4nsR6yRMWsf1dSoUqvRp5i-ixux4",
			},
		},
		err: nil,
	}

	p, err := roles.New(&roles.IdentityMap{
		TLS: roles.TLSIdentityMap{
			Enabled:                  true,
			DefaultAuthenticatedRole: "tls_authenticated",
			Roles: map[string][]string{
				"trusty-client": {"spiffe://trusty/client"},
			},
		},
		JWT: roles.JWTIdentityMap{
			Enabled:                  true,
			DefaultAuthenticatedRole: "jwt_authenticated",
			Roles: map[string][]string{
				"trusty-client": {"denis@trusty.ca"},
			},
		},
		DPoP: roles.JWTIdentityMap{
			Enabled:                  true,
			DefaultAuthenticatedRole: "dpop_authenticated",
			Roles: map[string][]string{
				"trusty-admin": {"denis@trusty.ca"},
			},
		},
	}, mock)
	require.NoError(t, err)

	t.Run("default role http", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		setAuthorizationHeader(r, "AccessToken123")
		assert.True(t, p.ApplicableForRequest(r))

		id, err := p.IdentityFromRequest(r)
		require.NoError(t, err)
		assert.Equal(t, "jwt_authenticated", id.Role())
		assert.Equal(t, "denis@trusty.com", id.Subject())
	})

	t.Run("default role dpop", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodPost, "https://api.test.proveid.dev/v1/dpop/token", nil)
		setAuthorizationDPoPHeader(r, "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRwb3Arand0IiwgImp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIk1wTmlIR1RkXzNYY240NDVVR0FlN09KY1NTekFXU2JSUWFXdWlZcW5kYzQiLCAieSI6ICJlOUMzWVAwMkdHOHVhUE5fZEUzOUNESEs3cDFyQm1HZXVUcXptNEZSMGI4In19.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9hcGkudGVzdC5wcm92ZWlkLmRldi92MS9kcG9wL3Rva2VuIiwiaWF0IjoxNjQ1MjA0OTI3LCJqdGkiOiIxQlJNbUZHSkVZX01MN3pLZjEwaWhxVTJuRjk0Wk01clhyUnlET1g0Rk0wIn0.mMUL2A-TE1L7i8J9cbxLAiuDOT0OpnATcaoyQKpq_ji7FO8WsFV_rf2TIFugA9NV4lk-QfBJAse5Ny5pRtHVLg", "AccessToken123")
		assert.True(t, p.ApplicableForRequest(r))

		dpop.TimeNowFn = func() time.Time {
			return time.Unix(1645204927, 0)
		}
		id, err := p.IdentityFromRequest(r)
		require.NoError(t, err)
		assert.Equal(t, "dpop_authenticated", id.Role())
		assert.Equal(t, "denis@trusty.com", id.Subject())
	})

	t.Run("default role grpc", func(t *testing.T) {
		ctx := context.Background()
		assert.False(t, p.ApplicableForContext(ctx))
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "AccessToken123"))

		id, err := p.IdentityFromContext(ctx)
		require.NoError(t, err)
		assert.Equal(t, "jwt_authenticated", id.Role())
		assert.Equal(t, "denis@trusty.com", id.Subject())
	})

	t.Run("tls:trusty-client", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)

		u, _ := url.Parse("spiffe://trusty/client")
		state := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{
					URIs: []*url.URL{u},
				},
			},
		}
		r.TLS = state

		id, err := p.IdentityFromRequest(r)
		require.NoError(t, err)
		assert.Equal(t, "trusty-client", id.Role())

		//
		// gRPC
		//
		ctx := createPeerContext(context.Background(), state)
		id, err = p.IdentityFromContext(ctx)
		require.NoError(t, err)
		assert.Equal(t, "trusty-client", id.Role())
	})
}

func Test_DPoPInvalid(t *testing.T) {
	t.Run("invaliddpop", func(t *testing.T) {
		mock := mockJWT{
			claims: jwt.MapClaims{
				"sub": "denis@trusty.com",
				"cnf": "C8kBamVR4FbaWBy4nsR6yRMWsf1dSoUqvRp5i-ixux4=",
			},
			err: nil,
		}

		p, err := roles.New(&roles.IdentityMap{
			TLS: roles.TLSIdentityMap{
				Enabled: false,
			},
			JWT: roles.JWTIdentityMap{
				Enabled: false,
			},
			DPoP: roles.JWTIdentityMap{
				Enabled:                  true,
				DefaultAuthenticatedRole: "dpop_authenticated",
				Roles: map[string][]string{
					"trusty-admin": {"denis@trusty.ca"},
				},
			},
		}, mock)
		require.NoError(t, err)

		r, _ := http.NewRequest(http.MethodPost, "https://api.test.proveid.dev/v1/dpop/token", nil)
		setAuthorizationDPoPHeader(r, "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRwb3Arand0IiwgImp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIk1wTmlIR1RkXzNYY240NDVVR0FlN09KY1NTekFXU2JSUWFXdWlZcW5kYzQiLCAieSI6ICJlOUMzWVAwMkdHOHVhUE5fZEUzOUNESEs3cDFyQm1HZXVUcXptNEZSMGI4In19.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9hcGkudGVzdC5wcm92ZWlkLmRldi92MS9kcG9wL3Rva2VuIiwiaWF0IjoxNjQ1MjA0OTI3LCJqdGkiOiIxQlJNbUZHSkVZX01MN3pLZjEwaWhxVTJuRjk0Wk01clhyUnlET1g0Rk0wIn0.mMUL2A-TE1L7i8J9cbxLAiuDOT0OpnATcaoyQKpq_ji7FO8WsFV_rf2TIFugA9NV4lk-QfBJAse5Ny5pRtHVLg", "AccessToken123")
		assert.True(t, p.ApplicableForRequest(r))

		dpop.TimeNowFn = func() time.Time {
			return time.Unix(1645204927, 0)
		}
		_, err = p.IdentityFromRequest(r)
		require.EqualError(t, err, "dpop: invalid cnf claim")
	})
	t.Run("dpop_mismatch", func(t *testing.T) {
		mock := mockJWT{
			claims: jwt.MapClaims{
				"sub": "denis@trusty.com",
				"cnf": map[string]interface{}{
					dpop.CnfThumbprint: "mismatch",
				},
			},
			err: nil,
		}

		p, err := roles.New(&roles.IdentityMap{
			TLS: roles.TLSIdentityMap{
				Enabled: false,
			},
			JWT: roles.JWTIdentityMap{
				Enabled: false,
			},
			DPoP: roles.JWTIdentityMap{
				Enabled:                  true,
				DefaultAuthenticatedRole: "dpop_authenticated",
				Roles: map[string][]string{
					"trusty-admin": {"denis@trusty.ca"},
				},
			},
		}, mock)
		require.NoError(t, err)

		r, _ := http.NewRequest(http.MethodPost, "https://api.test.proveid.dev/v1/dpop/token", nil)
		setAuthorizationDPoPHeader(r, "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRwb3Arand0IiwgImp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIk1wTmlIR1RkXzNYY240NDVVR0FlN09KY1NTekFXU2JSUWFXdWlZcW5kYzQiLCAieSI6ICJlOUMzWVAwMkdHOHVhUE5fZEUzOUNESEs3cDFyQm1HZXVUcXptNEZSMGI4In19.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9hcGkudGVzdC5wcm92ZWlkLmRldi92MS9kcG9wL3Rva2VuIiwiaWF0IjoxNjQ1MjA0OTI3LCJqdGkiOiIxQlJNbUZHSkVZX01MN3pLZjEwaWhxVTJuRjk0Wk01clhyUnlET1g0Rk0wIn0.mMUL2A-TE1L7i8J9cbxLAiuDOT0OpnATcaoyQKpq_ji7FO8WsFV_rf2TIFugA9NV4lk-QfBJAse5Ny5pRtHVLg", "AccessToken123")
		assert.True(t, p.ApplicableForRequest(r))

		dpop.TimeNowFn = func() time.Time {
			return time.Unix(1645204927, 0)
		}
		_, err = p.IdentityFromRequest(r)
		require.EqualError(t, err, "dpop: thumbprint mismatch")
	})
}

func TestTLSOnly(t *testing.T) {
	p, err := roles.New(&roles.IdentityMap{
		TLS: roles.TLSIdentityMap{
			Enabled:                  true,
			DefaultAuthenticatedRole: "tls_authenticated",
			Roles: map[string][]string{
				"trusty-client": {"spiffe://trusty/client"},
			},
		},
	}, nil)
	require.NoError(t, err)

	t.Run("default role http", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		setAuthorizationHeader(r, "AccessToken123")
		assert.False(t, p.ApplicableForRequest(r))

		id, err := p.IdentityFromRequest(r)
		require.NoError(t, err)
		assert.Equal(t, "guest", id.Role())
		assert.NotEmpty(t, id.Subject())
	})

	t.Run("default role grpc", func(t *testing.T) {
		ctx := context.Background()
		assert.False(t, p.ApplicableForContext(ctx))
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "AccessToken123"))

		id, err := p.IdentityFromContext(ctx)
		require.NoError(t, err)
		assert.Equal(t, "guest", id.Role())
		assert.Empty(t, id.Subject())
	})

	t.Run("tls:trusty-client", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)

		u, _ := url.Parse("spiffe://trusty/client")
		state := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{
					URIs: []*url.URL{u},
				},
			},
		}
		r.TLS = state

		assert.True(t, p.ApplicableForRequest(r))

		id, err := p.IdentityFromRequest(r)
		require.NoError(t, err)
		assert.Equal(t, "trusty-client", id.Role())

		//
		// gRPC
		//
		ctx := createPeerContext(context.Background(), state)
		assert.True(t, p.ApplicableForContext(ctx))
		id, err = p.IdentityFromContext(ctx)
		require.NoError(t, err)
		assert.Equal(t, "trusty-client", id.Role())
	})

	t.Run("tls:invalid", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)

		u, _ := url.Parse("spiffe://trusty/client")
		state := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{
					URIs: []*url.URL{u, u}, // spiffe must have only one URI
				},
			},
		}
		r.TLS = state

		assert.True(t, p.ApplicableForRequest(r))

		id, err := p.IdentityFromRequest(r)
		require.NoError(t, err)
		assert.Equal(t, "guest", id.Role())

		//
		// gRPC
		//
		ctx := createPeerContext(context.Background(), state)
		assert.True(t, p.ApplicableForContext(ctx))
		id, err = p.IdentityFromContext(ctx)
		require.NoError(t, err)
		assert.Equal(t, "guest", id.Role())
	})

}

func createPeerContext(ctx context.Context, TLS *tls.ConnectionState) context.Context {
	creds := credentials.TLSInfo{
		State: *TLS,
	}
	p := &peer.Peer{
		AuthInfo: creds,
	}
	return peer.NewContext(ctx, p)
}

// setAuthorizationHeader applies Authorization header
func setAuthorizationHeader(r *http.Request, token string) {
	r.Header.Set(header.Authorization, header.Bearer+" "+token)
}

// setAuthorizationDPoPHeader applies Authorization header
func setAuthorizationDPoPHeader(r *http.Request, dpop, token string) {
	r.Header.Set(header.DPoP, dpop)
	r.Header.Set(header.Authorization, header.DPoP+" "+token)
}

type mockJWT struct {
	claims jwt.MapClaims
	err    error
}

func (m mockJWT) ParseToken(authorization string, cfg jwt.VerifyConfig) (jwt.MapClaims, error) {
	return m.claims, m.err
}
