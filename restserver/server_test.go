package restserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/metrics"
	"github.com/effective-security/porto/pkg/tlsconfig"
	rest "github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var tlsConnectionForAdmin = &tls.ConnectionState{
	PeerCertificates: []*x509.Certificate{
		{
			Subject: pkix.Name{
				CommonName:   "Admin Trusted",
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
				CommonName:   "Admin Untrusted",
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
				CommonName:   "Client User",
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
				CommonName:   "Client Untrusted",
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

	if _, ok := any(server).(rest.Server); !ok {
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
	assert.Same(t, cfg, server.Config())

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

	if _, ok := any(server).(rest.Server); !ok {
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
	body, err := io.ReadAll(resp.Body)
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
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR2, syscall.SIGABRT)
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
	t.Parallel()
	trusted, err := identity.ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	cfg := &serverConfig{
		BindAddr: "hostname:8081",
	}

	server, err := rest.New("wrong", "", cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, server)

	t.Run("without XForwardedProto", func(t *testing.T) {
		t.Parallel()
		r, err := http.NewRequest(http.MethodGet, "/get/GET", nil)
		require.NoError(t, err)

		u := rest.GetServerURL(server, r, "/another/location")
		require.NotNil(t, u)

		assert.Equal(t, fmt.Sprintf("%s://%s/another/location", server.Protocol(), cfg.BindAddr), u.String())
	})

	t.Run("with XForwardedProto", func(t *testing.T) {
		t.Parallel()
		r, err := http.NewRequest(http.MethodGet, "/get/GET", nil)
		require.NoError(t, err)
		r.Header.Set(header.XForwardedProto, "https")
		r.RemoteAddr = "10.0.0.2:123"
		r = r.WithContext(identity.WithTrustedProxies(r.Context(), trusted))

		u := rest.GetServerURL(server, r, "/another/location")
		require.NotNil(t, u)

		assert.Equal(t, "https://hostname:8081/another/location", u.String())
	})

	t.Run("with XForwardedProto and Host", func(t *testing.T) {
		t.Parallel()
		r, err := http.NewRequest(http.MethodGet, "/get/GET", nil)
		require.NoError(t, err)
		r.Header.Set(header.XForwardedProto, "https")
		r.RemoteAddr = "10.0.0.2:123"
		r = r.WithContext(identity.WithTrustedProxies(r.Context(), trusted))
		r.Host = "localhost"

		u := rest.GetServerURL(server, r, "/another/location")
		require.NotNil(t, u)

		assert.Equal(t, "https://localhost/another/location", u.String())
	})

	t.Run("untrusted peer ignores forwarded protocol", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/get/GET", nil)
		r.RemoteAddr = "198.51.100.7:123"
		r.Header.Set(header.XForwardedProto, "https")
		r = r.WithContext(identity.WithTrustedProxies(r.Context(), trusted))
		u := rest.GetServerURL(server, r, "/another/location")
		assert.Equal(t, server.Protocol(), u.Scheme)
	})

	t.Run("invalid forwarded protocol", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/get/GET", nil)
		r.RemoteAddr = "10.0.0.2:123"
		r.Header.Set(header.XForwardedProto, "javascript")
		r = r.WithContext(identity.WithTrustedProxies(r.Context(), trusted))
		u := rest.GetServerURL(server, r, "/another/location")
		assert.Equal(t, server.Protocol(), u.Scheme)
	})
}

func TestHTTPServerTrustedProxies(t *testing.T) {
	t.Parallel()
	cfg := &serverConfig{BindAddr: "127.0.0.1:0"}
	server, err := rest.New("test", "", cfg, nil)
	require.NoError(t, err)
	trust, err := identity.ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	assert.Same(t, server, server.WithTrustedProxies(trust))

	var got string
	server.WithIdentityProvider(func(r *http.Request) (identity.Identity, error) {
		got = identity.ClientIPFromRequest(r)
		return nil, nil
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.2:123"
	r.Header.Set(header.XForwardedFor, "192.168.1.4")
	server.NewMux().ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, "192.168.1.4", got)
}

func TestCustomMuxTrustedProxies(t *testing.T) {
	t.Parallel()
	cfg := &serverConfig{BindAddr: testutils.CreateBindAddr("127.0.0.1")}
	server, err := rest.New("test", "", cfg, nil)
	require.NoError(t, err)
	trust, err := identity.ParseTrustedProxies([]string{"127.0.0.1/32"})
	require.NoError(t, err)
	server.WithTrustedProxies(trust).WithMuxFactory(muxer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(identity.ClientIPFromRequest(r)))
		assert.NoError(t, err)
	})))
	require.NoError(t, server.StartHTTP())
	defer server.StopHTTP()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+cfg.BindAddr+"/", nil)
	require.NoError(t, err)
	req.Header.Set(header.XForwardedFor, "192.168.1.4")
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.4", string(body))
}

func Test_GetServerBaseURL(t *testing.T) {
	t.Parallel()

	tcases := []struct {
		bindAddr string
		expHost  string
		expURL   string
	}{
		{
			bindAddr: "hostname:8081",
			expHost:  "hostname",
			expURL:   "http://hostname:8081",
		},
		{
			bindAddr: "[::1]:8443",
			expHost:  "::1",
			expURL:   "http://[::1]:8443",
		},
		{
			bindAddr: "::1",
			expHost:  "::1",
			expURL:   "http://[::1]:443",
		},
	}

	for _, tc := range tcases {
		t.Run(tc.bindAddr, func(t *testing.T) {
			t.Parallel()

			server, err := rest.New("v1.0.123", "", &serverConfig{BindAddr: tc.bindAddr}, nil)
			require.NoError(t, err)

			base := rest.GetServerBaseURL(server)
			assert.Equal(t, tc.expURL, base.String())
			assert.Equal(t, tc.expHost, base.Hostname())
			assert.Equal(t, server.Port(), base.Port())

			// without a request host, GetServerURL falls back to the bind address
			r, err := http.NewRequest(http.MethodGet, "/get/GET", nil)
			require.NoError(t, err)
			u := rest.GetServerURL(server, r, "/another/location")
			assert.Equal(t, tc.expURL+"/another/location", u.String())
		})
	}
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
	im := metrics.NewInmemSink(time.Minute, 5*time.Minute)
	// Runtime metrics would add samples to the exact comparisons.
	mcfg := metrics.DefaultConfig("authztest")
	mcfg.EnableRuntimeMetrics = false
	_, err := metrics.NewGlobal(mcfg, im)
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

	// snapshot returns the count of every sample and counter key, summed
	// over all intervals, so a run that crosses an interval boundary still
	// sees every emission.
	snapshot := func() map[string]int {
		counts := map[string]int{}
		for _, interval := range im.Data() {
			for k, v := range interval.Samples {
				counts[k] += v.Count
			}
			for k, v := range interval.Counters {
				counts[k] += v.Count
			}
		}
		return counts
	}
	// assertRecorded checks that exactly want was recorded since before.
	assertRecorded := func(t *testing.T, before map[string]int, want map[string]int) {
		t.Helper()
		got := map[string]int{}
		for k, v := range snapshot() {
			if d := v - before[k]; d != 0 {
				got[k] = d
			}
		}
		assert.Equal(t, want, got)
	}
	// request returns the perf sample and role counter keys of one request.
	request := func(labels, role string) map[string]int {
		return map[string]int{
			"authztest_http_requests_perf;" + labels:                   1,
			"authztest_http_requests_role;" + labels + ";role=" + role: 1,
		}
	}

	tlsCfg, err := tlsconfig.NewServerTLSFromFiles(
		"testdata/test-server.pem",
		"testdata/test-server-key.pem",
		"testdata/test-server-rootca.pem",
		"testdata/test-server.pem",
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
		cid := w.Header().Get(header.XCorrelationID)
		assert.NotEmpty(t, cid)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, fmt.Sprintf(`{"code":"not_ready","request_id":"%s","message":"the service is not ready yet"}`, cid), w.Body.String())
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
		before := snapshot()
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		cid := w.Header().Get(header.XCorrelationID)
		assert.NotEmpty(t, cid)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, fmt.Sprintf(`{"code":"unauthorized","request_id":"%s","message":"guest role not allowed"}`, cid), w.Body.String())
		assertRecorded(t, before, request("verb=GET;status=401;uri=unknown", "guest"))
	})

	t.Run("must_have_TLS", func(t *testing.T) {
		server, _ := startServer(true, identityMapperFromCNMust)
		defer server.StopHTTP()
		assert.True(t, server.IsReady())

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		before := snapshot()
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		// The identity mapper error is answered inside the outer metrics
		// handler, before the role is known: counted as guest.
		assertRecorded(t, before, request("verb=GET;status=401;uri=unknown", "guest"))
	})

	server, _ := startServer(true, identityMapperFromCN)
	defer server.StopHTTP()
	assert.True(t, server.IsReady())

	t.Run("admin_to_allow_200", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		r.TLS = tlsConnectionForAdmin
		before := snapshot()
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusOK, w.Code)

		assertRecorded(t, before, request("verb=GET;status=200;uri=/v1/allow", "admin"))
	})

	t.Run("any_root_admin_to_allow_200", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		r.TLS = tlsConnectionForAdminUntrusted
		before := snapshot()
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, `{"Method":"GET","Path":"/v1/allow"}`, w.Body.String())

		assertRecorded(t, before, request("verb=GET;status=200;uri=/v1/allow", "admin"))
	})

	t.Run("client_to_allow_403", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		r.TLS = tlsConnectionForClient
		before := snapshot()
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		cid := w.Header().Get(header.XCorrelationID)
		assert.NotEmpty(t, cid)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, fmt.Sprintf(`{"code":"forbidden","request_id":"%s","message":"client role not allowed"}`, cid), w.Body.String())
		assertRecorded(t, before, request("verb=GET;status=403;uri=unknown", "client"))
	})

	t.Run("other_org_client_to_allow_403", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allow", nil)
		r.TLS = tlsConnectionForClientFromOtherOrg
		before := snapshot()
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		cid := w.Header().Get(header.XCorrelationID)
		assert.NotEmpty(t, cid)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, fmt.Sprintf(`{"code":"forbidden","request_id":"%s","message":"client role not allowed"}`, cid), w.Body.String())
		assertRecorded(t, before, request("verb=GET;status=403;uri=unknown", "client"))
	})

	t.Run("client_to_allowany_200", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/v1/allowany", nil)
		r.TLS = tlsConnectionForClient
		before := snapshot()
		server.ServeHTTP(w, r)
		//assert.NotEmpty(t, w.Header().Get(header.XHostname))
		assert.NotEmpty(t, w.Header().Get(header.XCorrelationID))
		assert.Equal(t, http.StatusOK, w.Code)

		assertRecorded(t, before, request("verb=GET;status=200;uri=/v1/allowany", "client"))
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
		role = "user"

		if strings.Contains(name, "Admin") {
			role = "admin"
		} else if strings.Contains(name, "Client") {
			role = "client"
		}

	}
	return identity.NewIdentity(role, name, "", nil, "", "", identity.MethodCertificate), nil
}

func identityMapperFromCNMust(r *http.Request) (identity.Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("missing client certificate")
	}
	return identity.NewIdentity("user", r.TLS.PeerCertificates[0].Subject.CommonName, "", nil, "", "", identity.MethodCertificate), nil
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

// preflightService registers OPTIONS and GET handlers on a protected path
// and counts how often they run.
type preflightService struct {
	calls atomic.Int32
}

func (s *preflightService) Name() string  { return "preflighttest" }
func (s *preflightService) IsReady() bool { return true }
func (s *preflightService) Close()        {}

func (s *preflightService) Register(r rest.Router) {
	h := func(w http.ResponseWriter, r *http.Request, _ rest.Params) {
		s.calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}
	r.OPTIONS("/v1/private", h)
	r.GET("/v1/private", h)
}

func TestServer_CORSPreflightAuthz(t *testing.T) {
	const origin = "https://app.example.com"
	az, err := authz.New(&authz.Config{Allow: []string{"/v1/private:admin"}})
	require.NoError(t, err)
	admin := identity.NewIdentity("admin", "admin", "", nil, "", "", identity.MethodCertificate)

	start := func(t *testing.T, cors *rest.CORSOptions) (*rest.HTTPServer, *preflightService) {
		cfg := &serverConfig{
			BindAddr: testutils.CreateBindAddr(""),
			Services: []string{"preflighttest"},
		}
		server, err := rest.New("v1.0.123", "127.0.0.1", cfg, nil)
		require.NoError(t, err)
		server.WithAuthz(az).WithCORS(cors)
		svc := &preflightService{}
		server.AddService(svc)
		require.NoError(t, server.StartHTTP())
		t.Cleanup(server.StopHTTP)
		for i := 0; i < 10 && !server.IsReady(); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		require.True(t, server.IsReady())
		return server, svc
	}
	preflight := func() *http.Request {
		r := httptest.NewRequest(http.MethodOptions, "/v1/private", nil)
		r.Header.Set(header.Origin, origin)
		r.Header.Set(header.AccessControlRequestMethod, http.MethodGet)
		return r
	}
	serve := func(server *rest.HTTPServer, r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		return w
	}

	t.Run("cors disabled: OPTIONS is authorized", func(t *testing.T) {
		server, svc := start(t, nil)

		w := serve(server, preflight())
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), `"code":"unauthorized"`)
		assert.Equal(t, int32(0), svc.calls.Load(), "a forged preflight must not reach the OPTIONS handler")

		w = serve(server, identity.WithTestIdentity(preflight(), admin))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, int32(1), svc.calls.Load())
	})

	t.Run("cors enabled: preflight is answered before authz", func(t *testing.T) {
		server, svc := start(t, &rest.CORSOptions{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{http.MethodGet, http.MethodOptions},
		})

		w := serve(server, preflight())
		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, int32(0), svc.calls.Load(), "the CORS middleware must answer the preflight itself")

		// Denied actual requests carry CORS headers, so browsers can read them.
		r := httptest.NewRequest(http.MethodGet, "/v1/private", nil)
		r.Header.Set(header.Origin, origin)
		w = serve(server, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, int32(0), svc.calls.Load())

		w = serve(server, identity.WithTestIdentity(r, admin))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, int32(1), svc.calls.Load())
	})

	t.Run("options passthrough: OPTIONS is authorized", func(t *testing.T) {
		server, svc := start(t, &rest.CORSOptions{
			AllowedOrigins:     []string{"*"},
			AllowedMethods:     []string{http.MethodGet, http.MethodOptions},
			OptionsPassthrough: true,
		})

		w := serve(server, preflight())
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, int32(0), svc.calls.Load(), "a passed-through preflight must be authorized")

		w = serve(server, identity.WithTestIdentity(preflight(), admin))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, int32(1), svc.calls.Load())
	})
}
