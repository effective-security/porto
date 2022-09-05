package restserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/effective-security/metrics"
	"github.com/effective-security/porto/pkg/tlsconfig"
	rest "github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const projectPath = "../"

var tlsConnectionForAdmin = &tls.ConnectionState{
	PeerCertificates: []*x509.Certificate{
		{
			Subject: pkix.Name{
				CommonName:   "admin",
				Organization: []string{"effective-security"},
			},
		},
	},
	VerifiedChains: [][]*x509.Certificate{
		{
			{
				Subject: pkix.Name{
					CommonName:   "[TEST] Root CA",
					Organization: []string{"effective-security"},
				},
			},
		},
	},
}

var tlsConnectionForAdminUntrusted = &tls.ConnectionState{
	PeerCertificates: []*x509.Certificate{
		{
			Subject: pkix.Name{
				CommonName:   "admin",
				Organization: []string{"effective-security"},
			},
		},
	},
	VerifiedChains: [][]*x509.Certificate{
		{
			{
				Subject: pkix.Name{
					CommonName:   "[TEST] Untrusted Root CA",
					Organization: []string{"effective-security"},
				},
			},
		},
	},
}

var tlsConnectionForClient = &tls.ConnectionState{
	PeerCertificates: []*x509.Certificate{
		{
			Subject: pkix.Name{
				CommonName:   "client",
				Organization: []string{"effective-security"},
			},
		},
	},
	VerifiedChains: [][]*x509.Certificate{
		{
			{
				Subject: pkix.Name{
					CommonName:   "[TEST] Root CA",
					Organization: []string{"effective-security"},
				},
			},
		},
	},
}

var tlsConnectionForClientFromOtherOrg = &tls.ConnectionState{
	PeerCertificates: []*x509.Certificate{
		{
			Subject: pkix.Name{
				CommonName:   "client",
				Organization: []string{"someorg"},
			},
		},
	},
	VerifiedChains: [][]*x509.Certificate{
		{
			{
				Subject: pkix.Name{
					CommonName:   "[TEST] Root CA",
					Organization: []string{"effective-security"},
				},
			},
		},
	},
}

func Test_NewServer(t *testing.T) {
	cfg := &serverConfig{
		BindAddr: testutils.CreateBindAddr(""),
	}

	server, err := rest.New("v1.0.123", "", cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, server)

	if _, ok := interface{}(server).(rest.Server); !ok {
		require.Fail(t, "ensure interface")
	}

	require.NoError(t, err)
	assert.NotNil(t, server.Version)
	assert.NotNil(t, server.HostName)
	assert.NotNil(t, server.LocalIP)
	assert.NotNil(t, server.Port)
	assert.NotNil(t, server.Protocol)
	assert.NotNil(t, server.StartedAt)
	assert.NotNil(t, server.Uptime)
	assert.NotNil(t, server.Service)
	assert.NotNil(t, server.IsReady)
	assert.NotNil(t, server.AddService)
	assert.NotNil(t, server.StartHTTP)
	assert.NotNil(t, server.StopHTTP)
	assert.NotNil(t, server.HTTPConfig)
	assert.NotNil(t, server.OnEvent)
	assert.NotEmpty(t, server.Version())
	assert.NotEmpty(t, server.HostName())
	assert.NotEmpty(t, server.LocalIP())
	assert.NotEmpty(t, server.Port())
	assert.Equal(t, "http", server.Protocol())
	assert.NotNil(t, server.StartedAt())
	assert.Nil(t, server.Service("abc"))
	assert.False(t, server.IsReady())
	assert.NotNil(t, server.HTTPConfig())
	assert.Equal(t, cfg, server.HTTPConfig())

	assert.Equal(t, fmt.Sprintf("http://%s:%s", server.HostName(), server.Port()), rest.GetServerBaseURL(server).String())

	//	assert.NotNil(t, server.AddService())
	err = server.StartHTTP()
	require.NoError(t, err)

	for i := 0; i < 30 && !server.IsReady(); i++ {
		time.Sleep(1 * time.Second)
	}
	require.True(t, server.IsReady())

	server.StopHTTP()
}

func Test_NewServerWithGracefulShutdownSet(t *testing.T) {
	cfg := &serverConfig{
		BindAddr: testutils.CreateBindAddr("127.0.0.1"),
	}

	server, err := rest.New("v1.0.123", "", cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, server)

	server.WithShutdownTimeout(time.Second * 5)

	if _, ok := interface{}(server).(rest.Server); !ok {
		require.Fail(t, "ensure interface")
	}

	require.NoError(t, err)
	assert.NotNil(t, server.Version)
	assert.NotNil(t, server.HostName)
	assert.NotNil(t, server.LocalIP)
	assert.NotNil(t, server.Port)
	assert.NotNil(t, server.Protocol)
	assert.NotNil(t, server.StartedAt)
	assert.NotNil(t, server.Uptime)
	assert.NotNil(t, server.Service)
	assert.NotNil(t, server.IsReady)
	assert.NotNil(t, server.AddService)
	assert.NotNil(t, server.StartHTTP)
	assert.NotNil(t, server.StopHTTP)
	assert.NotNil(t, server.HTTPConfig)
	assert.NotNil(t, server.OnEvent)
	assert.NotEmpty(t, server.Version())
	assert.NotEmpty(t, server.HostName())
	assert.NotEmpty(t, server.LocalIP())
	assert.NotEmpty(t, server.Port())
	assert.Equal(t, "http", server.Protocol())
	assert.NotNil(t, server.StartedAt())
	assert.Nil(t, server.Service("abc"))
	assert.False(t, server.IsReady())
	assert.NotNil(t, server.HTTPConfig())
	assert.Equal(t, cfg, server.HTTPConfig())

	assert.Equal(t, fmt.Sprintf("%s://127.0.0.1:%s", server.Protocol(), server.Port()), rest.GetServerBaseURL(server).String())

	//	assert.NotNil(t, server.AddService())
	err = server.StartHTTP()
	require.NoError(t, err)

	for i := 0; i < 30 && !server.IsReady(); i++ {
		time.Sleep(1 * time.Second)
	}
	require.True(t, server.IsReady())

	server.StopHTTP()
}

func Test_NewServerWithCustomHandler(t *testing.T) {
	cfg := &serverConfig{
		BindAddr: testutils.CreateBindAddr("127.0.0.1"),
	}

	server, err := rest.New("v1.0.123", "", cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, server)
	svc := NewService(server)
	server.AddService(svc)

	defaultHandler := server.NewMux()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "test", "value in context")
		r = r.WithContext(ctx)
		defaultHandler.ServeHTTP(w, r)
	})
	server.WithMuxFactory(muxer(handler))

	err = server.StartHTTP()
	require.NoError(t, err)

	for i := 0; i < 30 && !server.IsReady(); i++ {
		time.Sleep(1 * time.Second)
	}
	require.True(t, server.IsReady())

	url := fmt.Sprintf("%s://127.0.0.1:%s/v1/test", server.Protocol(), server.Port())
	resp, err := http.Get(url)
	require.NoError(t, err)
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "value in context")

	sigs := make(chan os.Signal, 2)
	go func() {
		// Send STOP signal after few seconds,
		// in production the service should listen to
		// os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGUSR2, syscall.SIGABRT events
		time.Sleep(3 * time.Second)
		fmt.Println("sending syscall.SIGTERM signal")
		sigs <- syscall.SIGTERM
	}()

	// register for signals, and wait to be shutdown
	signal.Notify(sigs, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGUSR2, syscall.SIGABRT)
	// Block until a signal is received.
	<-sigs
	server.StopHTTP()
}

func Test_TLSConfig(t *testing.T) {
	cfg := &serverConfig{
		BindAddr: ":8081",
	}

	tlsConfig := &tls.Config{}
	server, err := rest.New("v1.0.123", "", cfg, tlsConfig)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.NotNil(t, server.TLSConfig)
	assert.Equal(t, tlsConfig, server.TLSConfig())
}

func Test_ResolveTCPAddr(t *testing.T) {
	cfg := &serverConfig{
		Name:     "invalid",
		BindAddr: "0-0-0-0",
	}

	server, err := rest.New("wrong", "", cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, server)

	err = server.StartHTTP()
	assert.EqualError(t, err, `unable to resolve address: address 0-0-0-0: missing port in address`)
}

func Test_GetServerURL(t *testing.T) {
	cfg := &serverConfig{
		BindAddr: "hostname:8081",
	}

	server, err := rest.New("wrong", "", cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, server)

	t.Run("without XForwardedProto", func(t *testing.T) {
		r, err := http.NewRequest(http.MethodGet, "/get/GET", nil)
		require.NoError(t, err)

		u := rest.GetServerURL(server, r, "/another/location")
		require.NotNil(t, u)

		assert.Equal(t, fmt.Sprintf("%s://%s/another/location", server.Protocol(), cfg.BindAddr), u.String())
	})

	t.Run("with XForwardedProto", func(t *testing.T) {
		r, err := http.NewRequest(http.MethodGet, "/get/GET", nil)
		require.NoError(t, err)
		r.Header.Set(header.XForwardedProto, "https")

		u := rest.GetServerURL(server, r, "/another/location")
		require.NotNil(t, u)

		assert.Equal(t, "https://hostname:8081/another/location", u.String())
	})

	t.Run("with XForwardedProto", func(t *testing.T) {
		r, err := http.NewRequest(http.MethodGet, "/get/GET", nil)
		require.NoError(t, err)
		r.Header.Set(header.XForwardedProto, "https")
		r.Host = "localhost"

		u := rest.GetServerURL(server, r, "/another/location")
		require.NotNil(t, u)

		assert.Equal(t, "https://localhost/another/location", u.String())
	})
}

type testMuxer struct {
	handler http.Handler
}

func (tm *testMuxer) NewMux() http.Handler {
	return tm.handler
}

func muxer(handler http.Handler) *testMuxer {
	return &testMuxer{handler: handler}
}

type response struct {
	Method string
	Path   string
}

func Test_Authz(t *testing.T) {
	im := metrics.NewInmemSink(time.Minute, time.Minute)
	_, err := metrics.NewGlobal(metrics.DefaultConfig("authztest"), im)
	require.NoError(t, err)

	defer func() {
		md := im.Data()
		if len(md) > 0 {
			for k := range md[0].Gauges {
				t.Log("Gauge:", k)
			}
			for k := range md[0].Counters {
				t.Log("Counter:", k)
			}
			for k := range md[0].Samples {
				t.Log("Sample:", k)
			}
		}
	}()

	assertSample := func(key string) {
		md := im.Data()
		require.NotEqual(t, 0, len(md))

		_, exists := md[0].Samples[key]
		assert.True(t, exists, "sample metric not found: %s", key)
	}
	assertCounter := func(key string, expectedCount int) {
		md := im.Data()
		require.NotEqual(t, 0, len(md))

		s, exists := md[0].Counters[key]
		if assert.True(t, exists, "counter metric not found: %s", key) {
			assert.Equal(t, expectedCount, s.Count, "unexpected count for metric %s", key)
		}
	}

	tlsCfg, err := tlsconfig.NewServerTLSFromFiles(
		"testdata/test-server.pem",
		"testdata/test-server-key.pem",
		"testdata/test-server-rootca.pem",
		tls.RequireAndVerifyClientCert,
	)
	require.NoError(t, err)

	cfg := &serverConfig{
		BindAddr: testutils.CreateBindAddr(""),
		Services: []string{"authztest"},
	}
	authz, err := authz.New(&authz.Config{
		Allow:        []string{"/v1/allow:admin"},
		AllowAny:     []string{"/v1/allowany"},
		AllowAnyRole: []string{"/v1/allowanyrole"},
		LogAllowed:   true,
		LogDenied:    true,
	})
	require.NoError(t, err)

	startServer := func(ready bool, idprov identity.ProviderFromRequest) (*rest.HTTPServer, *serviceX) {
		cfg.BindAddr = testutils.CreateBindAddr("")

		server, err := rest.New("v1.0.123", "127.0.0.1", cfg, tlsCfg)
		require.NoError(t, err)
		require.NotNil(t, server)
		server.WithAuthz(authz)

		if idprov != nil {
			server.WithIdentityProvider(idprov)
		}

		service := newService(t, server, "authztest", ready)
		server.AddService(service)

		err = server.StartHTTP()
		require.NoError(t, err)

		if ready {
			for i := 0; i < 10 && !server.IsReady(); i++ {
				time.Sleep(500 * time.Millisecond)
			}
			require.True(t, server.IsReady())
		}

		return server, service
	}

	t.Run("service not ready", func(t *testing.T) {
		server, _ := startServer(false, nil)
		defer server.StopHTTP()

		assert.False(t, server.IsReady())

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allowany", nil)
		server.ServeHTTP(w, r)

		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, `{"code":"not_ready","message":"the service is not ready yet"}`, w.Body.String())
	})

	t.Run("connection is not over TLS", func(t *testing.T) {
		server, _ := startServer(true, nil)
		defer server.StopHTTP()

		assert.True(t, server.IsReady())

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allowany", nil)
		server.ServeHTTP(w, r)

		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("guest_to_allow_401", func(t *testing.T) {
		server, _ := startServer(true, nil)
		defer server.StopHTTP()
		assert.True(t, server.IsReady())

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		r.TLS = tlsConnectionForClient
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `{"code":"unauthorized","message":"guest/client role not allowed"}`, w.Body.String())

		assertCounter("authztest.http.request.status.failed;method=GET;role=guest;status=401;uri=/v1/allow", 1)
	})

	t.Run("must_have_TLS", func(t *testing.T) {
		server, _ := startServer(true, identityMapperFromCNMust)
		defer server.StopHTTP()
		assert.True(t, server.IsReady())

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		assertCounter("authztest.http.request.status.failed;method=GET;role=guest;status=401;uri=/v1/allow", 1)
	})

	server, _ := startServer(true, identityMapperFromCN)
	defer server.StopHTTP()
	assert.True(t, server.IsReady())

	t.Run("admin_to_allow_200", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		r.TLS = tlsConnectionForAdmin
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusOK, w.Code)

		assertCounter("authztest.http.request.status.successful;method=GET;role=admin;status=200;uri=/v1/allow", 1)
		assertSample("authztest.http.request.perf;method=GET;role=admin;status=200;uri=/v1/allow")
	})

	t.Run("any_root_admin_to_allow_200", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		r.TLS = tlsConnectionForAdminUntrusted
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, `{"Method":"GET","Path":"/v1/allow"}`, w.Body.String())

		assertCounter("authztest.http.request.status.failed;method=GET;role=guest;status=401;uri=/v1/allow", 1)
	})

	t.Run("client_to_allow_401", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		r.TLS = tlsConnectionForClient
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `{"code":"unauthorized","message":"client role not allowed"}`, w.Body.String())

		assertCounter("authztest.http.request.status.failed;method=GET;role=guest;status=401;uri=/v1/allow", 1)
	})

	t.Run("other_org_client_to_allow_401", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		r.TLS = tlsConnectionForClientFromOtherOrg
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `{"code":"unauthorized","message":"client role not allowed"}`, w.Body.String())

		assertCounter("authztest.http.request.status.failed;method=GET;role=guest;status=401;uri=/v1/allow", 1)
	})

	t.Run("client_to_allowany_200", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allowany", nil)
		r.TLS = tlsConnectionForClient
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusOK, w.Code)

		assertCounter("authztest.http.request.status.successful;method=GET;role=client;status=200;uri=/v1/allowany", 1)
		assertSample("authztest.http.request.perf;method=GET;role=client;status=200;uri=/v1/allowany")
	})
}

func identityMapperFromCN(r *http.Request) (identity.Identity, error) {
	var role string
	var name string
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		name = identity.ClientIPFromRequest(r)
		role = identity.GuestRoleName
	} else {
		name = r.TLS.PeerCertificates[0].Subject.CommonName
		role = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return identity.NewIdentity(role, name, nil, "", ""), nil
}

func identityMapperFromCNMust(r *http.Request) (identity.Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("missing client certificate")
	}
	return identity.NewIdentity(r.TLS.PeerCertificates[0].Subject.CommonName,
		r.TLS.PeerCertificates[0].Subject.CommonName, nil, "", ""), nil
}

type serviceX struct {
	t      *testing.T
	server rest.Server
	name   string
	ready  bool
}

// newService returns ane instances of the Status service
func newService(t *testing.T, server rest.Server, name string, ready bool) *serviceX {
	svc := &serviceX{
		t:      t,
		server: server,
		name:   name,
		ready:  ready,
	}
	return svc
}

func (s *serviceX) setReady() {
	s.ready = true
}

// Name returns the service name
func (s *serviceX) Name() string {
	return s.name
}

// IsReady indicates that the service is ready to serve its end-points
func (s *serviceX) IsReady() bool {
	return s.ready
}

// Close the subservices and it's resources
func (s *serviceX) Close() {
}

// Register adds the server Status API endpoints to the overall URL router
func (s *serviceX) Register(r rest.Router) {
	r.GET("/v1/allow", s.handle())
	r.GET("/v1/allowany", s.handle())
	r.GET("/v1/allowanyrole", s.handle())
}

func (s *serviceX) handle() rest.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ rest.Params) {
		s.t.Logf("serviceX: %s %s", r.Method, r.URL.Path)
		res := &response{
			Method: r.Method,
			Path:   r.URL.Path,
		}

		marshal.WriteJSON(w, r, res)
	}
}
