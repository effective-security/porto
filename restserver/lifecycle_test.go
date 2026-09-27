package restserver_test

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	rest "github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lifecycleService struct {
	closed chan struct{}
}

func (s *lifecycleService) Name() string         { return "lifecycle" }
func (s *lifecycleService) Register(rest.Router) {}
func (s *lifecycleService) IsReady() bool        { return true }
func (s *lifecycleService) Close()               { close(s.closed) }

func TestStartHTTPReturnsPlainBindError(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	cfg := &serverConfig{BindAddr: listener.Addr().String()}
	server, err := rest.New("test", "127.0.0.1", cfg, nil)
	require.NoError(t, err)
	err = server.StartHTTP()
	require.ErrorContains(t, err, "unable to listen")
	assert.False(t, server.IsReady())

	require.NoError(t, listener.Close())
	require.NoError(t, server.StartHTTP())
	t.Cleanup(server.StopHTTP)
	assert.True(t, server.IsReady())
}

func TestStopHTTPBeforeStart(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{BindAddr: testutils.CreateBindAddr("127.0.0.1")}
	server, err := rest.New("test", "127.0.0.1", cfg, nil)
	require.NoError(t, err)
	server.StopHTTP()
	assert.False(t, server.IsReady())
	require.NoError(t, server.StartHTTP())
	server.StopHTTP()
	server.StopHTTP()
	assert.False(t, server.IsReady())
	require.ErrorContains(t, server.StartHTTP(), "already started")
}

func TestStopHTTPWaitsForStartedEvent(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{BindAddr: testutils.CreateBindAddr("127.0.0.1")}
	server, err := rest.New("test", "127.0.0.1", cfg, nil)
	require.NoError(t, err)

	events := make(chan rest.ServerEvent, 3)
	started := make(chan struct{})
	releaseStarted := make(chan struct{})
	server.OnEvent(rest.ServerStartedEvent, func(evt rest.ServerEvent) {
		events <- evt
		close(started)
		<-releaseStarted
	})
	server.OnEvent(rest.ServerStoppingEvent, func(evt rest.ServerEvent) { events <- evt })
	server.OnEvent(rest.ServerStoppedEvent, func(evt rest.ServerEvent) { events <- evt })
	require.NoError(t, server.StartHTTP())
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseStarted) })
		server.StopHTTP()
	})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("started handler did not run")
	}

	stopDone := make(chan struct{})
	go func() {
		server.StopHTTP()
		close(stopDone)
	}()
	select {
	case evt := <-events:
		assert.Equal(t, rest.ServerStartedEvent, evt)
	case <-time.After(2 * time.Second):
		t.Fatal("started event was not delivered")
	}
	select {
	case evt := <-events:
		t.Fatalf("event %v arrived before started callback returned", evt)
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-stopDone:
		t.Fatal("StopHTTP returned before started callback completed")
	default:
	}

	releaseOnce.Do(func() { close(releaseStarted) })
	select {
	case <-stopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("StopHTTP did not finish")
	}
	assert.Equal(t, rest.ServerStoppingEvent, <-events)
	assert.Equal(t, rest.ServerStoppedEvent, <-events)
}

func TestStopHTTPDrainsBeforeClosingServices(t *testing.T) {
	t.Parallel()

	cfg := &serverConfig{BindAddr: testutils.CreateBindAddr("127.0.0.1")}
	server, err := rest.New("test", "127.0.0.1", cfg, nil)
	require.NoError(t, err)
	server.WithShutdownTimeout(2 * time.Second)
	service := &lifecycleService{closed: make(chan struct{})}
	server.AddService(service)

	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	var releaseOnce sync.Once
	server.WithMuxFactory(muxer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-releaseRequest
		w.WriteHeader(http.StatusNoContent)
	})))
	stopping := make(chan struct{})
	server.OnEvent(rest.ServerStoppingEvent, func(rest.ServerEvent) { close(stopping) })
	require.NoError(t, server.StartHTTP())
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseRequest) })
		server.StopHTTP()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.BindAddr, nil)
	require.NoError(t, err)
	type response struct {
		resp *http.Response
		err  error
	}
	requestDone := make(chan response, 1)
	go func() {
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		requestDone <- response{resp: resp, err: err}
	}()
	select {
	case <-requestStarted:
	case <-ctx.Done():
		t.Fatal("request did not reach handler")
	}

	stopDone := make(chan struct{})
	go func() {
		server.StopHTTP()
		close(stopDone)
	}()
	select {
	case <-stopping:
	case <-ctx.Done():
		t.Fatal("server did not start stopping")
	}
	assert.False(t, server.IsReady())
	select {
	case <-service.closed:
		t.Fatal("service closed while request was active")
	default:
	}
	secondStopDone := make(chan struct{})
	go func() {
		server.StopHTTP()
		close(secondStopDone)
	}()
	select {
	case <-secondStopDone:
		t.Fatal("concurrent StopHTTP returned before request drained")
	case <-time.After(50 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(releaseRequest) })
	result := <-requestDone
	require.NoError(t, result.err)
	require.Equal(t, http.StatusNoContent, result.resp.StatusCode)
	require.NoError(t, result.resp.Body.Close())
	select {
	case <-stopDone:
	case <-ctx.Done():
		t.Fatal("server did not finish stopping")
	}
	select {
	case <-secondStopDone:
	case <-ctx.Done():
		t.Fatal("concurrent StopHTTP did not finish")
	}
	assert.True(t, !server.IsReady())
	select {
	case <-service.closed:
	default:
		t.Fatal("service was not closed after draining")
	}
}
