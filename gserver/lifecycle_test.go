package gserver

import (
	"bytes"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/transport"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/dig"
)

// The tests in this file that count process-wide goroutines (reloaders and
// servers) must not run in parallel with tests that start servers.

const (
	// reloaderFrame is the stack frame of the KeypairReloader polling goroutine.
	reloaderFrame = "tlsconfig.NewKeypairReloader.func"
	// grpcServeFrame and httpServeFrame are the accept loops serve starts.
	grpcServeFrame = "google.golang.org/grpc.(*Server).Serve("
	httpServeFrame = "net/http.(*Server).Serve("
	lifecycleWait  = 5 * time.Second
	lifecycleTick  = 10 * time.Millisecond
	// serveSettle is how long a goroutine that serve started is given to
	// appear in the stack dump.
	serveSettle = 100 * time.Millisecond
)

var lifecycleTLS = &TLSInfo{
	CertFile:      "testdata/test-server.pem",
	KeyFile:       "testdata/test-server-key.pem",
	TrustedCAFile: "testdata/test-server-rootca.pem",
}

// goroutinesWith counts the running goroutines whose stack contains frame.
func goroutinesWith(frame string) int {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return bytes.Count(buf[:n], []byte(frame))
		}
		buf = make([]byte, 2*len(buf))
	}
}

// reloaderGoroutines counts the running KeypairReloader polling goroutines.
func reloaderGoroutines() int {
	return goroutinesWith(reloaderFrame)
}

// serveGoroutines counts the running gRPC and HTTP server accept loops.
func serveGoroutines() int {
	return goroutinesWith(grpcServeFrame) + goroutinesWith(httpServeFrame)
}

// requireNoReloaders waits until no KeypairReloader goroutine runs;
// KeypairReloader.Close does not wait for its goroutine to exit.
func requireNoReloaders(t *testing.T, msg string) {
	t.Helper()
	require.Eventually(t, func() bool { return reloaderGoroutines() == 0 }, lifecycleWait, lifecycleTick, msg)
}

// requireClosesPromptly fails when Close does not return within lifecycleWait.
func requireClosesPromptly(t *testing.T, srv GServer) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Close()
	}()
	select {
	case <-done:
	case <-time.After(lifecycleWait):
		t.Fatal("Close did not return")
	}
}

// requireListenable fails when addr cannot be bound, i.e. a listener leaked.
func requireListenable(t *testing.T, addr, msg string) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	require.NoError(t, err, msg)
	require.NoError(t, l.Close())
}

// closableService counts its Close calls.
type closableService struct {
	name   string
	closes int
}

func (s *closableService) Name() string  { return s.name }
func (s *closableService) IsReady() bool { return true }
func (s *closableService) Close()        { s.closes++ }

func TestStartFailedFactoryClosesServices(t *testing.T) {
	t.Parallel()
	first := &closableService{name: "first"}
	factories := map[string]ServiceFactory{
		"first": func(server GServer) any {
			return func() { server.AddService(first) }
		},
		"second": func(GServer) any {
			return func() error { return errors.New("boom") }
		},
	}
	cfg := &Config{Services: []string{"first", "second"}}

	srv, err := Start("failed-factory", cfg, dig.New(), factories)
	require.Error(t, err)
	assert.ErrorContains(t, err, `service factory failed, server="failed-factory", service=second`)
	assert.Nil(t, srv)
	assert.Equal(t, 1, first.closes, "services created before the failure must be closed")

	cfg = &Config{Services: []string{"first", "missing"}}
	first.closes = 0
	srv, err = Start("missing-factory", cfg, dig.New(), factories)
	require.EqualError(t, err, `service factory is not registered: "missing"`)
	assert.Nil(t, srv)
	assert.Equal(t, 1, first.closes)
}

// TestCloseConcurrent releases overlapping Close calls from a barrier; run
// with -race, it checks that the teardown, including the TLS reloader, is
// serialized and that services are closed once.
func TestCloseConcurrent(t *testing.T) {
	requireNoReloaders(t, "a KeypairReloader from another test is still running")
	svc := &closableService{name: "svc"}
	factories := map[string]ServiceFactory{
		"svc": func(server GServer) any {
			return func() { server.AddService(svc) }
		},
	}
	cfg := &Config{
		ListenURLs: []string{"https://127.0.0.1:0"},
		Services:   []string{"svc"},
		ServerTLS:  lifecycleTLS,
	}
	srv, err := Start("concurrent-close", cfg, discoveryContainer(t), factories)
	require.NoError(t, err)
	e := srv.(*Server)

	const closers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range closers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			srv.Close()
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(lifecycleWait):
		t.Fatal("concurrent Close calls did not return")
	}

	assert.Equal(t, 1, svc.closes, "services must be closed once")
	assert.Nil(t, e.tlsInfo.Config())
	requireNoReloaders(t, "Close must stop the KeypairReloader")
}

func discoveryContainer(t *testing.T) *dig.Container {
	t.Helper()
	c := dig.New()
	require.NoError(t, c.Provide(func() discovery.Discovery { return discovery.New() }))
	return c
}

func TestCloseStopsTLSReloader(t *testing.T) {
	requireNoReloaders(t, "a KeypairReloader from another test is still running")
	cfg := &Config{
		ListenURLs: []string{"https://127.0.0.1:0"},
		ServerTLS:  lifecycleTLS,
	}
	srv, err := Start("tls-reloader", cfg, discoveryContainer(t), nil)
	require.NoError(t, err)
	e := srv.(*Server)
	require.NotNil(t, e.tlsInfo)
	assert.NotNil(t, e.tlsInfo.Config())
	assert.Equal(t, 1, reloaderGoroutines())

	requireClosesPromptly(t, srv)
	assert.Nil(t, e.tlsInfo.Config(), "Close must release the TLS config")
	requireNoReloaders(t, "Close must stop the KeypairReloader")

	// A second Close finds nothing left to release.
	requireClosesPromptly(t, srv)
}

func TestStartFailureReleasesResources(t *testing.T) {
	requireNoReloaders(t, "a KeypairReloader from another test is still running")
	addr := testutils.CreateBindAddr("127.0.0.1")
	cfg := &Config{
		ListenURLs: []string{"https://" + addr},
		ServerTLS:  lifecycleTLS,
	}
	// Without discovery.Discovery, Start fails after the listener is open.
	srv, err := Start("no-discovery", cfg, dig.New(), nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "unable to inject dependencies")
	assert.Nil(t, srv)

	requireListenable(t, addr, "Start must release its listener on failure")
	requireNoReloaders(t, "Start must stop the KeypairReloader on failure")

	// JWT identities without a jwt.Parser fail in the identity provider,
	// after discovery was injected.
	cfg.IdentityMap = &roles.IdentityMap{}
	cfg.IdentityMap.JWT.Enabled = true
	srv, err = Start("no-jwt-parser", cfg, discoveryContainer(t), nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "unable to create roles AuthZ: jwt: JWT parser is required")
	assert.Nil(t, srv)

	requireListenable(t, addr, "Start must release its listener on an identity provider error")
	requireNoReloaders(t, "Start must stop the KeypairReloader on an identity provider error")
}

func TestConfigureListenersCleansUpOnError(t *testing.T) {
	requireNoReloaders(t, "a KeypairReloader from another test is still running")
	addr := testutils.CreateBindAddr("127.0.0.1")
	cfg := &Config{
		ListenURLs: []string{"https://" + addr, "ftp://" + addr},
		ServerTLS:  lifecycleTLS,
	}
	sctxs, tlsInfo, err := configureListeners(cfg)
	require.EqualError(t, err, `unsupported URL scheme "ftp"`)
	assert.Nil(t, sctxs)
	assert.Nil(t, tlsInfo)

	requireListenable(t, addr, "the listener opened before the failure must be closed")
	requireNoReloaders(t, "the reloader started before the failure must be stopped")
}

// TestServeFailureUnblocksClose fails the TLS listener setup of a listener
// that serves both plaintext and TLS; serve must start no server and Close
// must still return.
func TestServeFailureUnblocksClose(t *testing.T) {
	requireNoReloaders(t, "a KeypairReloader from another test is still running")
	require.Eventually(t, func() bool { return serveGoroutines() == 0 }, lifecycleWait, lifecycleTick,
		"a server from another test is still running")
	addr := testutils.CreateBindAddr("127.0.0.1")
	cfg := &Config{
		ListenURLs: []string{"http://" + addr, "https://" + addr},
		ServerTLS:  lifecycleTLS,
	}
	e, err := newServer("serve-failure", cfg, nil, nil)
	require.NoError(t, err)
	e.identity, err = roles.New(&roles.IdentityMap{}, nil)
	require.NoError(t, err)
	require.Len(t, e.sctxs, 1)
	sctx := e.sctxs[addr]
	require.True(t, sctx.secure && sctx.insecure)

	// An empty TLSInfo makes transport.NewTLSListener, the last fallible
	// step, fail; it also closes the root listener, which Close closes again.
	sctx.tlsInfo = &transport.TLSInfo{}
	err = sctx.serve(e, e.errHandler)
	require.Error(t, err)
	assert.ErrorContains(t, err, "KeyFile and CertFile are not presented")

	// The plaintext servers were built but never started: a gRPC server
	// blocked in Accept on a cmux listener could not be stopped.
	assert.Never(t, func() bool { return serveGoroutines() > 0 }, serveSettle, lifecycleTick,
		"serve must not start a server when its setup fails")

	requireClosesPromptly(t, e)
	requireNoReloaders(t, "Close must stop the KeypairReloader")
}
