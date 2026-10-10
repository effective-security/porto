package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
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

	id := NewIdentity("netmgmt", "Ekspand", "org", nil, "", "", MethodNone)
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
		assert.Equal(t, "test", caller.UserAgent())
		assert.Equal(t, "/test", caller.Target())
	})
	rw := httptest.NewRecorder()
	handler := NewContextHandler(d, GuestIdentityMapper)
	r, err := http.NewRequest("GET", "/test", nil)
	require.NoError(t, err)
	r.RemoteAddr = "10.0.0.1"
	r.Header.Set("User-Agent", "test")
	r.Header.Set("X-Forwarded-For", "10.0.0.2")
	r.Header.Set("X-Real-Ip", "10.0.0.3")

	handler.ServeHTTP(rw, r)
}

func Test_AddToContext(t *testing.T) {
	ctx := AddToContext(
		context.Background(),
		NewRequestContext(NewIdentity("r", "n", "", map[string]any{"email": "test"}, "", "", MethodNone), "/test"),
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
		_, _ = unary(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
			rt := FromContext(ctx)
			require.NotNil(t, rt)
			require.NotNil(t, rt.Identity())
			assert.Equal(t, "guest", rt.Identity().Role())
			return nil, nil
		})
	})

	t.Run("with_custom_id", func(t *testing.T) {
		def := func(ctx context.Context, method string) (Identity, error) {
			return NewIdentity("test", "", "", nil, "", "", MethodNone), nil
		}
		unary := NewAuthUnaryInterceptor(def)
		handler := func(ctx context.Context, req any) (any, error) {
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
		_, err := unary(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
			return nil, errors.New("some error")
		})
		require.Error(t, err)
		// The mapper's text is logged, not returned.
		st := status.Convert(err)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Equal(t, "invalid identity", st.Message())
	})

	t.Run("with_httperror", func(t *testing.T) {
		shared := httperror.Forbidden("tenant disabled")
		def := func(ctx context.Context, method string) (Identity, error) {
			return nil, errors.Errorf("wrapped: %w", shared)
		}
		unary := NewAuthUnaryInterceptor(def)
		ctx := correlation.WithID(context.Background())
		_, err := unary(ctx, nil, info, func(ctx context.Context, req any) (any, error) {
			return nil, errors.New("some error")
		})
		require.Error(t, err)
		// An explicit httperror is the mapper's own client-safe answer.
		assert.Equal(t, "rpc error: code = PermissionDenied desc = tenant disabled", status.Convert(err).Err().Error())
		assert.Empty(t, shared.RequestID, "a mapper's shared error must not be modified")
	})

	t.Run("with_httperror_without_grpc_code", func(t *testing.T) {
		def := func(ctx context.Context, method string) (Identity, error) {
			return nil, httperror.New(http.StatusTeapot, "custom", "brew")
		}
		unary := NewAuthUnaryInterceptor(def)
		_, err := unary(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
			return nil, errors.New("some error")
		})
		require.Error(t, err)
		assert.Equal(t, "rpc error: code = Unauthenticated desc = brew", err.Error())
	})

	t.Run("with_httperror_without_http_status", func(t *testing.T) {
		def := func(ctx context.Context, method string) (Identity, error) {
			return nil, &httperror.Error{Code: "custom", Message: "brew"}
		}
		unary := NewAuthUnaryInterceptor(def)
		_, err := unary(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
			return nil, errors.New("some error")
		})
		require.Error(t, err)
		st := status.Convert(err)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Equal(t, "invalid identity", st.Message())
	})

	t.Run("with_typed_nil_httperror", func(t *testing.T) {
		def := func(ctx context.Context, method string) (Identity, error) {
			var typedNil *httperror.Error
			return nil, typedNil
		}
		unary := NewAuthUnaryInterceptor(def)
		_, err := unary(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
			return nil, errors.New("some error")
		})
		require.Error(t, err)
		st := status.Convert(err)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Equal(t, "invalid identity", st.Message())
	})

	t.Run("stream_with_error", func(t *testing.T) {
		def := func(ctx context.Context, method string) (Identity, error) {
			return nil, errors.New("invalid request")
		}
		stream := NewStreamServerInterceptor(def)
		called := false
		err := stream(nil, testStream{ctx: context.Background()}, &grpc.StreamServerInfo{FullMethod: "/test"}, func(srv any, ss grpc.ServerStream) error {
			called = true
			return nil
		})
		require.Error(t, err)
		assert.False(t, called)
		st := status.Convert(err)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Equal(t, "invalid identity", st.Message())
	})

	t.Run("trusted proxy metadata", func(t *testing.T) {
		trust, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
		require.NoError(t, err)
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 123}})
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-forwarded-for", "192.168.1.4"))
		interceptor := NewAuthUnaryInterceptor(GuestIdentityForContext, trust)
		_, err = interceptor(ctx, nil, info, func(ctx context.Context, _ any) (any, error) {
			assert.Equal(t, "192.168.1.4", FromContext(ctx).ClientIP())
			return nil, nil
		})
		require.NoError(t, err)
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
		require.Equal(t, http.StatusUnauthorized, w.Code)

		// The mapper's text is logged, not returned.
		assert.Equal(t, `{"code":"unauthorized","message":"invalid identity"}`, w.Body.String())
	})

	t.Run("mapper_httperror_without_status", func(t *testing.T) {
		// A malformed httperror (no HTTP status) must not reach WriteHeader.
		mapper := func(r *http.Request) (Identity, error) {
			return nil, &httperror.Error{Code: "custom", Message: "brew"}
		}
		handler := NewContextHandler(http.HandlerFunc(h), mapper)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `{"code":"unauthorized","message":"invalid identity"}`, w.Body.String())
	})

	t.Run("mapper_typed_nil_httperror", func(t *testing.T) {
		mapper := func(r *http.Request) (Identity, error) {
			var typedNil *httperror.Error
			return nil, typedNil
		}
		handler := NewContextHandler(http.HandlerFunc(h), mapper)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `{"code":"unauthorized","message":"invalid identity"}`, w.Body.String())
	})

	t.Run("mapper_httperror", func(t *testing.T) {
		shared := httperror.Forbidden("tenant disabled")
		mapper := func(r *http.Request) (Identity, error) {
			return nil, errors.Errorf("wrapped: %w", shared)
		}
		handler := NewContextHandler(http.HandlerFunc(h), mapper)
		ctx := correlation.WithID(context.Background())
		cid := correlation.ID(ctx)
		r := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, fmt.Sprintf(`{"code":"forbidden","request_id":"%s","message":"tenant disabled"}`, cid), w.Body.String())
		assert.Empty(t, shared.RequestID, "a mapper's shared error must not be modified")
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

// testStream is a grpc.ServerStream that only carries a context.
type testStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s testStream) Context() context.Context {
	return s.ctx
}

// TestRejectedIdentityLogsRemote checks that the WARNING lines of a
// rejected HTTP request and gRPC call carry the client IP resolved under
// the trusted proxy policy as remote, the field name of the access lines.
// It installs a process-global log formatter, so it is not parallel.
func TestRejectedIdentityLogsRemote(t *testing.T) {
	const (
		proxy  = "10.0.0.2"
		client = "203.0.113.9"
		path   = "/v1/items"
		method = "/pkg.Service/Method"
		// identityLogPkg is the package name of this package's logger
		identityLogPkg = "context"
	)
	var logs bytes.Buffer
	t.Cleanup(xlog.InstallFormatter(xlog.NewJSONFormatter(&logs)))
	trust, err := ParseTrustedProxies([]string{proxy + "/32"})
	require.NoError(t, err)
	deny := errors.New("invalid credentials")

	httpMapper := func(*http.Request) (Identity, error) { return nil, deny }
	h := NewTrustedProxyHandler(NewContextHandler(http.NotFoundHandler(), httpMapper), trust)
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = proxy + ":443"
	r.Header.Set(header.XForwardedFor, client)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)

	grpcMapper := func(context.Context, string) (Identity, error) { return nil, deny }
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(proxy), Port: 443}})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(header.XForwardedFor, client))
	_, err = NewAuthUnaryInterceptor(grpcMapper, trust)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
		func(context.Context, any) (any, error) { return nil, nil })
	require.Equal(t, codes.Unauthenticated, status.Code(err))

	// the lines of this package's logger; marshal logs the 401 too
	var got []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		entry := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &entry), line)
		if entry["pkg"] == identityLogPkg {
			// func of the HTTP line is a closure name, which changes when
			// an earlier closure is added
			delete(entry, "time")
			delete(entry, "func")
			got = append(got, entry)
		}
	}
	assert.Equal(t, []map[string]any{
		{
			"level":  "W",
			"pkg":    identityLogPkg,
			"reason": "identityMapper",
			"remote": client,
			"target": path,
			"err":    deny.Error(),
		},
		{
			"level":  "W",
			"pkg":    identityLogPkg,
			"reason": "access_denied",
			"method": method,
			"remote": client,
			"err":    deny.Error(),
		},
	}, got)
}
