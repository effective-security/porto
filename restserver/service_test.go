package restserver_test

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strconv"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/go-phorce/dolly/xhttp/retriable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testURL = "/v1/test"

// service defines the Status service
type service struct {
	server restserver.Server
}

// NewService returns ane instances of the Status service
func NewService(
	server restserver.Server,
) restserver.Service {
	if server == nil {
		panic("invalid parameter to NewService")
	}

	return &service{
		server: server,
	}
}

// Name returns the service name
func (s *service) Name() string {
	return "testService"
}

// IsReady indicates that the service is ready to serve its end-points
func (s *service) IsReady() bool {
	return true
}

// Close the subservices and it's resources
func (s *service) Close() {
}

// Register adds the endpoints to the overall URL router
func (s *service) Register(r restserver.Router) {
	r.GET(testURL, testHandler(s))
}

func testHandler(s *service) restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		//context.ForRequest(r)
		ctx := r.Context()
		v := ctx.Value("test")
		status := http.StatusOK
		if rc, ok := r.URL.Query()["rc"]; ok {
			if s, err := strconv.Atoi(rc[0]); err == nil {
				status = s
			}
		}

		w.Header().Set(header.ContentType, header.TextPlain)
		w.WriteHeader(status)
		fmt.Fprintf(w, "URL: %s\n", r.URL)
		fmt.Fprintf(w, "Method: %s\n", r.Method)
		fmt.Fprintf(w, "Agent: %s\n", r.UserAgent())
		fmt.Fprintf(w, "RemoteAddr: %s\n", r.RemoteAddr)
		fmt.Fprintf(w, "ContextValue: %s\n", v)
	}
}

type ctx struct {
}

func (c *ctx) SetHeaders(r *http.Request) {
}

func Test_ServerWithServicesOverHTTP(t *testing.T) {
	cfg := &serverConfig{
		BindAddr: ":8088",
	}

	startedCount := 0
	stoppedCount := 0

	server, err := restserver.New("v1.0.123", "127.0.0.1", cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, server)

	server.OnEvent(restserver.ServerStartedEvent, func(evt restserver.ServerEvent) {
		assert.Equal(t, restserver.ServerStartedEvent, evt)
		startedCount++
	})
	server.OnEvent(restserver.ServerStoppedEvent, func(evt restserver.ServerEvent) {
		assert.Equal(t, restserver.ServerStoppedEvent, evt)
		stoppedCount++
	})

	svc := NewService(server)
	server.AddService(svc)

	//	assert.NotNil(t, server.AddService())
	err = server.StartHTTP()
	require.NoError(t, err)

	for i := 0; i < 10 && !server.IsReady(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, server.IsReady())

	testHTTPService(t, server)
	testCORS(t, server, false)

	server.StopHTTP()

	assert.Equal(t, 1, startedCount)
	assert.Equal(t, 1, stoppedCount)
}

func Test_ServerWithCORS(t *testing.T) {
	cfg := &serverConfig{
		BindAddr: ":8088",
	}

	startedCount := 0
	stoppedCount := 0

	server, err := restserver.New("v1.0.123", "127.0.0.1", cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, server)

	server.WithCORS(&restserver.CORSOptions{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "OPTIONS", "POST"},
		AllowedHeaders: []string{header.ContentType, header.XDeviceID},
		ExposedHeaders: []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"},
	})

	server.OnEvent(restserver.ServerStartedEvent, func(evt restserver.ServerEvent) {
		assert.Equal(t, restserver.ServerStartedEvent, evt)
		startedCount++
	})
	server.OnEvent(restserver.ServerStoppedEvent, func(evt restserver.ServerEvent) {
		assert.Equal(t, restserver.ServerStoppedEvent, evt)
		stoppedCount++
	})

	svc := NewService(server)
	server.AddService(svc)

	//	assert.NotNil(t, server.AddService())
	err = server.StartHTTP()
	require.NoError(t, err)

	for i := 0; i < 10 && !server.IsReady(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, server.IsReady())

	testCORS(t, server, true)
	testHTTPService(t, server)

	server.StopHTTP()

	assert.Equal(t, 1, startedCount)
	assert.Equal(t, 1, stoppedCount)
}

func testHTTPService(t *testing.T, server restserver.Server) {
	resp, err := http.Get(fmt.Sprintf("%s://localhost:%s/v1/test", server.Protocol(), server.Port()))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	b, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	txt := string(b)
	assert.Contains(t, txt, "Method: GET")
}

func testCORS(t *testing.T, server restserver.Server, expected bool) {
	client := retriable.New()
	require.NotNil(t, client)

	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodOptions, "/v1/test", nil)
	require.NoError(t, err)

	r.Header.Set("Access-Control-Request-Method", "GET")
	r.Header.Set("Access-Control-Request-Headers", "content-type,x-device-id")
	r.Header.Set("Origin", "http://localhost:4200")

	server.ServeHTTP(w, r)

	h := w.Header()
	for k, v := range h {
		t.Logf("Header: %s = %q", k, v)
	}
	require.NoError(t, err)
	// TODO: test explicitly for 200 or 204
	assert.LessOrEqual(t, w.Code, http.StatusNoContent)

	debugResponse(t, w.Result(), true)

	if expected {
		assert.NotEmpty(t, h.Get("Access-Control-Allow-Origin"))
		assert.NotEmpty(t, h.Get("Access-Control-Allow-Methods"))
		assert.NotEmpty(t, h.Get("Access-Control-Allow-Headers"))
	} else {
		assert.NotEmpty(t, h.Get("Allow"))
		assert.Empty(t, h.Get("Access-Control-Allow-Origin"))
		assert.Empty(t, h.Get("Access-Control-Allow-Methods"))
		assert.Empty(t, h.Get("Access-Control-Allow-Headers"))
	}
}

func debugResponse(t *testing.T, w *http.Response, body bool) {
	b, err := httputil.DumpResponse(w, body)
	if assert.NoError(t, err) {
		t.Logf(string(b))
	}
}

func (s *testSuite) Test_ServerWithServicesOverHTTPS() {
	serverTlsCfg := &tlsConfig{
		CertFile:       s.serverCertFile,
		KeyFile:        s.serverKeyFile,
		TrustedCAFile:  s.rootsFile,
		WithClientAuth: true,
	}

	tlsInfo, tlsloader, err := createServerTLSInfo(serverTlsCfg)
	s.Require().NoError(err)
	defer tlsloader.Close()

	cfg := &serverConfig{
		BindAddr: getAvailableBinding(),
	}

	server, err := restserver.New("v1.0.123", "", cfg, tlsInfo)
	s.Require().NoError(err)
	s.Require().NotNil(server)
	s.Equal("https", server.Protocol())

	svc := NewService(server)
	server.AddService(svc)

	//	assert.NotNil(t, server.AddService())
	err = server.StartHTTP()
	s.Require().NoError(err)

	defer server.StopHTTP()

	for i := 0; i < 10 && !server.IsReady(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	s.Require().True(server.IsReady())

	s.T().Run("no client cert", func(t *testing.T) {
		_, err = http.Get(fmt.Sprintf("%s://localhost:%s/v1/test", server.Protocol(), server.Port()))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate signed by unknown authority")
	})

	s.T().Run("with client cert / trusted roots", func(t *testing.T) {
		clientTls, err := tlsconfig.NewClientTLSFromFiles(
			s.clientCertFile,
			s.clientKeyFile,
			s.rootsFile)
		require.NoError(t, err)

		client := retriable.New(retriable.WithTLS(clientTls))
		require.NotNil(t, client)

		hosts := []string{fmt.Sprintf("%s://localhost:%s", server.Protocol(), server.Port())}

		w := bytes.NewBuffer([]byte{})
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, status, err := client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		res := string(w.Bytes())
		assert.Contains(t, res, "GET")
	})
	s.T().Run("with client cert / untrusted root", func(t *testing.T) {
		clientTls, err := tlsconfig.NewClientTLSFromFiles(
			s.clientCertFile,
			s.clientKeyFile,
			s.clientRootFile)
		require.NoError(t, err)

		client := retriable.New().WithTLS(clientTls)
		require.NotNil(t, client)

		hosts := []string{fmt.Sprintf("%s://localhost:%s", server.Protocol(), server.Port())}

		w := bytes.NewBuffer([]byte{})

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, _, err = client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate signed by unknown authority")
	})
}

func (s *testSuite) Test_UntrustedServerWithServicesOverHTTPS() {
	serverTlsCfg := &tlsConfig{
		CertFile:       s.serverCertFile,
		KeyFile:        s.serverKeyFile,
		TrustedCAFile:  s.serverRootFile,
		WithClientAuth: true,
	}

	tlsInfo, tlsloader, err := createServerTLSInfo(serverTlsCfg)
	s.Require().NoError(err)
	defer tlsloader.Close()

	cfg := &serverConfig{
		BindAddr: getAvailableBinding(),
	}

	server, err := restserver.New("v1.0.123", "127.0.0.1", cfg, tlsInfo)
	s.Require().NoError(err)
	s.Require().NotNil(server)
	s.Equal("https", server.Protocol())

	svc := NewService(server)
	server.AddService(svc)

	//	assert.NotNil(t, server.AddService())
	err = server.StartHTTP()
	s.Require().NoError(err)

	defer server.StopHTTP()

	for i := 0; i < 10 && !server.IsReady(); i++ {
		time.Sleep(1 * time.Second)
	}
	s.Require().True(server.IsReady())

	s.T().Run("no client cert", func(t *testing.T) {
		_, err = http.Get(fmt.Sprintf("%s://localhost:%s/v1/test", server.Protocol(), server.Port()))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate signed by unknown authority")
	})

	s.T().Run("trusted server root", func(t *testing.T) {
		clientTls, err := tlsconfig.NewClientTLSFromFiles(
			s.clientCertFile,
			s.clientKeyFile,
			s.serverRootFile)
		require.NoError(t, err)

		client := retriable.New(retriable.WithTLS(clientTls))
		require.NotNil(t, client)

		hosts := []string{fmt.Sprintf("%s://localhost:%s", server.Protocol(), server.Port())}

		w := bytes.NewBuffer([]byte{})

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_, _, err = client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tls: bad certificate")
	})

	s.T().Run("untrusted server root", func(t *testing.T) {
		clientTls, err := tlsconfig.NewClientTLSFromFiles(
			s.clientCertFile,
			s.clientKeyFile,
			s.clientRootFile)
		require.NoError(t, err)

		client := retriable.New(retriable.WithTLS(clientTls))
		require.NotNil(t, client)

		hosts := []string{fmt.Sprintf("%s://localhost:%s", server.Protocol(), server.Port())}

		w := bytes.NewBuffer([]byte{})

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_, _, err = client.Request(ctx, http.MethodGet, hosts, "/v1/test", nil, w)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate signed by unknown authority")
	})
}

// returns free open TCP port
func getAvailableBinding() string {
	ln, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		panic("unable to get port: " + err.Error())
	}
	defer ln.Close()
	return ":" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}
