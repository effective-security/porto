package identity

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractIdentityFromRequest(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)

	t.Run("when IP is not set", func(t *testing.T) {
		idn, _ := GuestIdentityMapper(r)
		assert.Equal(t, "unknown:guest", idn.String())
	})

	t.Run("when IP is set", func(t *testing.T) {
		r.RemoteAddr = "10.0.1.2:443"

		idn, _ := GuestIdentityMapper(r)
		assert.Equal(t, "unknown:guest", idn.String())
	})

	t.Run("when TLS is set and defaultExtractor", func(t *testing.T) {
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{
					Subject: pkix.Name{
						CommonName:   "test",
						Organization: []string{"org"},
					},
				},
			},
		}

		idn, _ := GuestIdentityMapper(r)
		assert.Equal(t, "test:guest", idn.String())
	})
}

func Test_WithTestIdentityDirect(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)

	r = WithTestIdentity(r, NewIdentity("role1", "name1", "org1", nil, "", ""))
	ctx := FromRequest(r)

	assert.Equal(t, "org1/name1:role1", ctx.Identity().String())
	assert.Empty(t, correlation.ID(r.Context()))
}

func Test_NewIdentityWithClaims(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)

	u := jwt.MapClaims{
		"email":  "denis@ekspand.com",
		"tenant": "org",
	}
	r = WithTestIdentity(r, NewIdentity("role1", "name1", "", u, "", ""))
	ctx := FromRequest(r)
	assert.Equal(t, "name1:role1", ctx.Identity().String())
	assert.Equal(t, "denis@ekspand.com", ctx.Identity().Claims()["email"])
	assert.Equal(t, "org", ctx.Identity().Claims()["tenant"])
}

func Test_WithTestIdentityServeHTTP(t *testing.T) {
	d := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := FromRequest(r)
		assert.Equal(t, "org/name2:role1", caller.Identity().String())
	})
	rw := httptest.NewRecorder()
	handler := NewContextHandler(d, nil)
	r, _ := http.NewRequest("GET", "/test", nil)
	r = WithTestIdentity(r, NewIdentity("role1", "name2", "org", nil, "", ""))
	handler.ServeHTTP(rw, r)
}

func Test_IdentityString(t *testing.T) {
	assert.Equal(t, "org/name2:role1", NewIdentity("role1", "name2", "org", nil, "", "").String())
	assert.Equal(t, "name2:role1", NewIdentity("role1", "name2", "", nil, "", "").String())
	assert.Equal(t, "test", NewIdentity("test", "test", "", nil, "", "").String())
	assert.Equal(t, "unknown:test", NewIdentity("test", "", "", nil, "", "").String())
}
