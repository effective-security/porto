package gserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/tests/mockappcontainer"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartEmptyHTTP(t *testing.T) {
	cfg := &gserver.Config{
		ListenURLs: []string{testutils.CreateURL("http", ""), testutils.CreateURL("unix", "localhost")},
		Services:   []string{"test"},
		KeepAlive: gserver.KeepAliveCfg{
			MinTime:  time.Second,
			Interval: time.Second,
			Timeout:  time.Second,
		},
	}

	c := mockappcontainer.NewBuilder().
		WithJwtParser(nil).
		WithDiscovery(discovery.New()).
		Container()

	fact := map[string]gserver.ServiceFactory{
		"test": testServiceFactory,
	}
	srv, err := gserver.Start("Empty", cfg, c, fact)
	require.NoError(t, err)
	require.NotNil(t, srv)
	defer srv.Close()

	assert.Equal(t, "Empty", srv.Name())
	assert.NotNil(t, srv.Configuration())
	//srv.AddService(&service{})
	assert.NotNil(t, srv.Service("test"))
	assert.True(t, srv.IsReady())
	assert.True(t, srv.StartedAt().Unix() > 0)
	assert.NotEmpty(t, srv.ListenURLs())
	assert.NotEmpty(t, srv.Hostname())
	assert.NotEmpty(t, srv.LocalIP())
}

func TestRateLimit(t *testing.T) {
	enabled := true
	cfg := &gserver.Config{
		ListenURLs: []string{testutils.CreateURL("http", ""), testutils.CreateURL("unix", "localhost")},
		Services:   []string{"test"},
		KeepAlive: gserver.KeepAliveCfg{
			MinTime:  time.Second,
			Interval: time.Second,
			Timeout:  time.Second,
		},
		RateLimit: &gserver.RateLimit{
			Enabled:           &enabled,
			RequestsPerSecond: 1,
		},
	}

	c := mockappcontainer.NewBuilder().
		WithJwtParser(nil).
		WithDiscovery(discovery.New()).
		Container()

	fact := map[string]gserver.ServiceFactory{
		"test": testServiceFactory,
	}
	srv, err := gserver.Start("TestRateLimit", cfg, c, fact)
	require.NoError(t, err)
	require.NotNil(t, srv)
	defer srv.Close()

	assert.Equal(t, "TestRateLimit", srv.Name())
	assert.True(t, srv.IsReady())

	client, err := retriable.Default(cfg.ListenURLs[0])
	require.NoError(t, err)

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		hdr, status, err := client.Get(ctx, "/status", w)
		if i == 0 {
			assert.NoError(t, err)
			assert.Equal(t, "1", hdr.Get("RateLimit-Limit"))
			assert.Equal(t, "0", hdr.Get("RateLimit-Remaining"))
		} else {
			assert.EqualError(t, err, "You have reached maximum request limit.")
			assert.Equal(t, "1.00", hdr.Get("X-Rate-Limit-Limit"))
			assert.Equal(t, "1", hdr.Get("X-Rate-Limit-Duration"))
			assert.Equal(t, http.StatusTooManyRequests, status)
		}
	}
}

func TestStartEmptyHTTPS(t *testing.T) {
	cfg := &gserver.Config{
		ListenURLs: []string{testutils.CreateURL("https", ""), testutils.CreateURL("unixs", "localhost")},
		ServerTLS: &gserver.TLSInfo{
			CertFile:      "testdata/test-server.pem",
			KeyFile:       "testdata/test-server-key.pem",
			TrustedCAFile: "testdata/test-server-rootca.pem",
		},
	}

	c := mockappcontainer.NewBuilder().
		WithJwtParser(nil).
		WithDiscovery(discovery.New()).
		Container()

	srv, err := gserver.Start("EmptyHTTPS", cfg, c, nil)
	require.NoError(t, err)
	require.NotNil(t, srv)
	defer srv.Close()

	assert.Equal(t, "EmptyHTTPS", srv.Name())
}

type tservice struct{}

// Name returns the service name
func (s *tservice) Name() string  { return "test" }
func (s *tservice) IsReady() bool { return true }
func (s *tservice) Close()        {}

func (s *tservice) RegisterRoute(r restserver.Router) {
	r.GET("/status", s.handler())
}

func (s *tservice) handler() restserver.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
		w.Header().Set(header.ContentType, header.TextPlain)
		w.Write([]byte("alive"))
	}
}

func testServiceFactory(server gserver.GServer) any {
	return func() {
		svc := &tservice{}
		server.AddService(svc)
	}
}
