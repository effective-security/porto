package identity

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/x/netutil"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractIdentityFromRequest(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)

	t.Run("when IP is not set", func(t *testing.T) {
		ip, err := netutil.GetLocalIP()
		require.NoError(t, err)

		idn, _ := GuestIdentityMapper(r)
		assert.Equal(t, "guest/ip:"+ip, idn.String())
	})

	t.Run("when IP is set", func(t *testing.T) {
		r.RemoteAddr = "10.0.1.2:443"

		idn, _ := GuestIdentityMapper(r)
		assert.Equal(t, "guest/ip:10.0.1.2", idn.String())
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
		assert.Equal(t, "guest/test", idn.String())
	})
}

func Test_WithTestIdentityDirect(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)

	r = WithTestIdentity(r, NewIdentity("role1", "name1", nil, "", ""))
	ctx := FromRequest(r)

	assert.Equal(t, "role1/name1", ctx.Identity().String())
	assert.Empty(t, correlation.ID(r.Context()))
}

func Test_NewIdentityWithClaims(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)

	u := jwt.MapClaims{"email": "denis@ekspand.com"}
	r = WithTestIdentity(r, NewIdentity("role1", "name1", u, "", ""))
	ctx := FromRequest(r)
	assert.Equal(t, "role1/name1", ctx.Identity().String())
	assert.Equal(t, "denis@ekspand.com", ctx.Identity().Claims()["email"])
}

func Test_WithTestIdentityServeHTTP(t *testing.T) {
	d := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := FromRequest(r)
		assert.Equal(t, "role1/name2", caller.Identity().String())
	})
	rw := httptest.NewRecorder()
	handler := NewContextHandler(d, nil)
	r, _ := http.NewRequest("GET", "/test", nil)
	r = WithTestIdentity(r, NewIdentity("role1", "name2", nil, "", ""))
	handler.ServeHTTP(rw, r)
}

func Test_IdentityString(t *testing.T) {
	assert.Equal(t, "role1/name2", NewIdentity("role1", "name2", nil, "", "").String())
	assert.Equal(t, "test", NewIdentity("test", "test", nil, "", "").String())
	assert.Equal(t, "test", NewIdentity("test", "", nil, "", "").String())
}
