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

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	rc := m.Run()
	os.Exit(rc)
}

func Test_Identity(t *testing.T) {
	i := identity{role: "netmgmt", name: "Ekspand"}
	assert.Equal(t, "netmgmt", i.Role())
	assert.Equal(t, "Ekspand", i.Name())
	assert.Equal(t, "netmgmt/Ekspand", i.String())

	id := NewIdentity("netmgmt", "Ekspand", "123456")
	assert.Equal(t, "netmgmt", id.Role())
	assert.Equal(t, "Ekspand", id.Name())
	assert.Equal(t, "123456", id.UserID())
	assert.Equal(t, "netmgmt/Ekspand", id.String())
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
		assert.NotEmpty(t, caller.CorrelationID())
	})
	rw := httptest.NewRecorder()
	handler := NewContextHandler(d, GuestIdentityMapper)
	r, err := http.NewRequest("GET", "/test", nil)
	require.NoError(t, err)
	r.RemoteAddr = "10.0.0.1"

	handler.ServeHTTP(rw, r)
}

func TestCorrelationID(t *testing.T) {
	d := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := FromRequest(r)
		cid := caller.CorrelationID()
		w.Header().Set(header.XCorrelationID, cid)
	})

	t.Run("no_from_client", func(t *testing.T) {
		rw := httptest.NewRecorder()
		handler := NewContextHandler(d, GuestIdentityMapper)
		r, _ := http.NewRequest("GET", "/test", nil)

		handler.ServeHTTP(rw, r)
		cid := rw.Header().Get(header.XCorrelationID)
		assert.Len(t, cid, 8)
	})

	t.Run("show_from_client", func(t *testing.T) {
		rw := httptest.NewRecorder()
		handler := NewContextHandler(d, GuestIdentityMapper)
		r, _ := http.NewRequest("GET", "/test", nil)
		r.Header.Set(header.XCorrelationID, "1234") // short incoming

		handler.ServeHTTP(rw, r)
		cid := rw.Header().Get(header.XCorrelationID)
		assert.Len(t, cid, 8+5)
	})

	t.Run("long_from_client", func(t *testing.T) {
		rw := httptest.NewRecorder()
		handler := NewContextHandler(d, GuestIdentityMapper)
		r, _ := http.NewRequest("GET", "/test", nil)
		r.Header.Set(header.XCorrelationID, "1234jsehdrlcfkjwhelckjqhewlkcjhqwlekcjhqeq")

		handler.ServeHTTP(rw, r)
		cid := rw.Header().Get(header.XCorrelationID)
		assert.Len(t, cid, 8+1+8)
	})
}

func Test_AddToContext(t *testing.T) {
	ctx := AddToContext(
		context.Background(),
		NewRequestContext(NewIdentity("r", "n", "u")),
	)

	rqCtx := FromContext(ctx)
	require.NotNil(t, rqCtx)

	identity := rqCtx.Identity()
	require.Equal(t, "n", identity.Name())
	require.Equal(t, "r", identity.Role())
	require.Equal(t, "u", identity.UserID())
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
			Name: identity.Name(),
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
	t.Run("default_guest", func(t *testing.T) {
		unary := NewAuthUnaryInterceptor(GuestIdentityForContext)
		unary(context.Background(), nil, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
			rt := FromContext(ctx)
			require.NotNil(t, rt)
			require.NotNil(t, rt.Identity())
			assert.Equal(t, "guest", rt.Identity().Role())
			return nil, nil
		})
	})

	t.Run("with_custom_id", func(t *testing.T) {
		def := func(ctx context.Context) (Identity, error) {
			return NewIdentity("test", "", ""), nil
		}
		unary := NewAuthUnaryInterceptor(def)
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			rt := FromContext(ctx)
			require.NotNil(t, rt)
			require.NotNil(t, rt.Identity())
			assert.Equal(t, "test", rt.Identity().Role())
			return nil, nil
		}
		unary(context.Background(), nil, nil, handler)
	})

	t.Run("with_error", func(t *testing.T) {
		def := func(ctx context.Context) (Identity, error) {
			return nil, errors.New("invalid request")
		}
		unary := NewAuthUnaryInterceptor(def)
		_, err := unary(context.Background(), nil, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
			return nil, errors.New("some error")
		})
		require.Error(t, err)
		assert.Equal(t, "rpc error: code = PermissionDenied desc = unable to get identity: invalid request", err.Error())
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
			Name: identity.Name(),
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
		require.Equal(t, http.StatusUnauthorized, w.Code)

		assert.Equal(t, `{"code":"unauthorized","message":"request denied for this identity"}`, w.Body.String())
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
	return identity{name: name, role: role}, nil
}

func identityMapperFromCNMust(r *http.Request) (Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("missing client certificate")
	}
	return identity{name: r.TLS.PeerCertificates[0].Subject.CommonName, role: r.TLS.PeerCertificates[0].Subject.CommonName}, nil
}
