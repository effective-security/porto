package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestMain(m *testing.M) {
	rc := m.Run()
	os.Exit(rc)
}

func Test_Identity(t *testing.T) {
	i := identity{role: "netmgmt", subject: "Ekspand"}
	assert.Equal(t, "netmgmt", i.Role())
	assert.Equal(t, "Ekspand", i.Subject())
	assert.Equal(t, "Ekspand:netmgmt", i.String())
	assert.Empty(t, i.Tenant())

	id := NewIdentity("netmgmt", "Ekspand", "org", nil, "", "")
	assert.Equal(t, "netmgmt", id.Role())
	assert.Equal(t, "Ekspand", id.Subject())
	assert.Equal(t, "org", id.Tenant())
	assert.Equal(t, "org/Ekspand:netmgmt", id.String())
}

func Test_ForRequest(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	ctx := FromRequest(r)
	assert.NotNil(t, ctx)
}

func Test_ClientIP(t *testing.T) {
	d := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := FromRequest(r)
		assert.Equal(t, "10.0.0.1", caller.ClientIP())
	})
	rw := httptest.NewRecorder()
	handler := NewContextHandler(d, GuestIdentityMapper)
	r, err := http.NewRequest("GET", "/test", nil)
	require.NoError(t, err)
	r.RemoteAddr = "10.0.0.1"

	handler.ServeHTTP(rw, r)
}

func Test_AddToContext(t *testing.T) {
	ctx := AddToContext(
		context.Background(),
		NewRequestContext(NewIdentity("r", "n", "", map[string]interface{}{"email": "test"}, "", "")),
	)

	rqCtx := FromContext(ctx)
	require.NotNil(t, rqCtx)

	identity := rqCtx.Identity()
	require.Equal(t, "n", identity.Subject())
	require.Equal(t, "r", identity.Role())
	require.Equal(t, "test", identity.Claims().String("email"))
}

func Test_FromContext(t *testing.T) {
	type roleName struct {
		Role string `json:"role,omitempty"`
		Name string `json:"name,omitempty"`
	}

	h := func(w http.ResponseWriter, r *http.Request) {
		ctx := FromContext(r.Context())

		identity := ctx.Identity()
		res := &roleName{
			Role: identity.Role(),
			Name: identity.Subject(),
		}
		marshal.WriteJSON(w, r, res)
	}

	handler := NewContextHandler(http.HandlerFunc(h), GuestIdentityMapper)

	t.Run("default_extractor", func(t *testing.T) {
		r, err := http.NewRequest(http.MethodGet, "/test", nil)
		require.NoError(t, err)

		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{
					Subject: pkix.Name{
						CommonName:   "es",
						Organization: []string{"org"},
					},
				},
			},
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code)

		resp := w.Result()
		defer resp.Body.Close()

		rn := &roleName{}
		require.NoError(t, marshal.Decode(resp.Body, rn))
		assert.Equal(t, GuestRoleName, rn.Role)
		assert.Equal(t, "es", rn.Name)
	})
}

func Test_grpcFromContext(t *testing.T) {
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test",
	}

	t.Run("default_guest", func(t *testing.T) {
		unary := NewAuthUnaryInterceptor(GuestIdentityForContext)
		_, _ = unary(context.Background(), nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
			rt := FromContext(ctx)
			require.NotNil(t, rt)
			require.NotNil(t, rt.Identity())
			assert.Equal(t, "guest", rt.Identity().Role())
			return nil, nil
		})
	})

	t.Run("with_custom_id", func(t *testing.T) {
		def := func(ctx context.Context, method string) (Identity, error) {
			return NewIdentity("test", "", "", nil, "", ""), nil
		}
		unary := NewAuthUnaryInterceptor(def)
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			rt := FromContext(ctx)
			require.NotNil(t, rt)
			require.NotNil(t, rt.Identity())
			assert.Equal(t, "test", rt.Identity().Role())
			return nil, nil
		}
		unary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test"}, handler)
	})

	t.Run("with_error", func(t *testing.T) {
		def := func(ctx context.Context, method string) (Identity, error) {
			return nil, errors.New("invalid request")
		}
		unary := NewAuthUnaryInterceptor(def)
		_, err := unary(context.Background(), nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, errors.New("some error")
		})
		require.Error(t, err)
		assert.Equal(t, "some error", err.Error())
	})
}

func Test_RequestorIdentity(t *testing.T) {
	type roleName struct {
		Role string `json:"role,omitempty"`
		Name string `json:"name,omitempty"`
	}

	h := func(w http.ResponseWriter, r *http.Request) {
		ctx := FromRequest(r)
		identity := ctx.Identity()
		res := &roleName{
			Role: identity.Role(),
			Name: identity.Subject(),
		}
		marshal.WriteJSON(w, r, res)
	}

	t.Run("default_extractor", func(t *testing.T) {
		handler := NewContextHandler(http.HandlerFunc(h), GuestIdentityMapper)
		r, err := http.NewRequest(http.MethodGet, "/test", nil)
		require.NoError(t, err)

		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{
					Subject: pkix.Name{
						CommonName:   "es",
						Organization: []string{"org"},
					},
				},
			},
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code)

		resp := w.Result()
		defer resp.Body.Close()

		rn := &roleName{}
		require.NoError(t, marshal.Decode(resp.Body, rn))
		assert.Equal(t, GuestRoleName, rn.Role)
		assert.Equal(t, "es", rn.Name)
	})

	t.Run("cn_extractor", func(t *testing.T) {
		handler := NewContextHandler(http.HandlerFunc(h), identityMapperFromCN)
		r, err := http.NewRequest(http.MethodGet, "/test", nil)
		require.NoError(t, err)

		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{
					Subject: pkix.Name{
						CommonName:   "cn-es",
						Organization: []string{"org"},
					},
				},
			},
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code)

		resp := w.Result()
		defer resp.Body.Close()

		rn := &roleName{}
		require.NoError(t, marshal.Decode(resp.Body, rn))
		assert.Equal(t, "cn-es", rn.Role)
		assert.Equal(t, "cn-es", rn.Name)
	})

	t.Run("cn_extractor_must", func(t *testing.T) {
		handler := NewContextHandler(http.HandlerFunc(h), identityMapperFromCNMust)
		r, err := http.NewRequest(http.MethodGet, "/test", nil)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code)

		assert.Equal(t, `{"role":"guest"}`, w.Body.String())
	})
	t.Run("ForRequest", func(t *testing.T) {
		r, err := http.NewRequest(http.MethodGet, "/test", nil)
		require.NoError(t, err)

		ctx := FromRequest(r)
		assert.Equal(t, GuestRoleName, ctx.Identity().Role())
	})
}

func identityMapperFromCN(r *http.Request) (Identity, error) {
	var role string
	var name string
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		name = ClientIPFromRequest(r)
		role = GuestRoleName
	} else {
		name = r.TLS.PeerCertificates[0].Subject.CommonName
		role = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return identity{subject: name, role: role}, nil
}

func identityMapperFromCNMust(r *http.Request) (Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("missing client certificate")
	}
	return identity{subject: r.TLS.PeerCertificates[0].Subject.CommonName, role: r.TLS.PeerCertificates[0].Subject.CommonName}, nil
}
