package gserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/porto/restserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type shutdownService struct {
	closed atomic.Bool
	serve  http.HandlerFunc
}

func (s *shutdownService) Name() string  { return "shutdown" }
func (s *shutdownService) IsReady() bool { return true }
func (s *shutdownService) Close()        { s.closed.Store(true) }
func (s *shutdownService) RegisterRoute(r restserver.Router) {
	r.GET("/shutdown", func(w http.ResponseWriter, req *http.Request, _ restserver.Params) {
		s.serve(w, req)
	})
}

func startShutdownServer(t *testing.T, secure bool, svc *shutdownService, timeout time.Duration) (*Server, net.Conn) {
	t.Helper()
	cfg := &Config{
		ListenURLs: []string{"http://127.0.0.1:0"},
		Services:   []string{svc.Name()},
	}
	cfg.Timeout.Shutdown = timeout
	if secure {
		cfg.ListenURLs = []string{"https://127.0.0.1:0"}
		cfg.ServerTLS = lifecycleTLS
	}
	factories := map[string]ServiceFactory{
		svc.Name(): func(server GServer) any {
			return func() { server.AddService(svc) }
		},
	}
	srv, err := Start("shutdown", cfg, discoveryContainer(t), factories)
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	e := srv.(*Server)
	addr := e.Listeners[0].Addr().String()
	dialer := &net.Dialer{Timeout: lifecycleWait}
	var conn net.Conn
	if secure {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{InsecureSkipVerify: true},
		}
		conn, err = tlsDialer.DialContext(t.Context(), "tcp", addr)
	} else {
		conn, err = dialer.DialContext(t.Context(), "tcp", addr)
	}
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	require.NoError(t, conn.SetDeadline(time.Now().Add(lifecycleWait)))
	return e, conn
}

const shutdownRequest = "GET /shutdown HTTP/1.1\r\nHost: localhost\r\n\r\n"

func TestCloseDrainsHTTPBeforeServices(t *testing.T) {
	t.Parallel()
	for _, secure := range []bool{false, true} {
		name := "plaintext"
		if secure {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			started, release := make(chan struct{}), make(chan struct{})
			svc := &shutdownService{}
			svc.serve = func(w http.ResponseWriter, r *http.Request) {
				close(started)
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				assert.False(t, svc.closed.Load(), "services must remain open during drain")
				w.WriteHeader(http.StatusNoContent)
			}
			srv, conn := startShutdownServer(t, secure, svc, lifecycleWait)
			_, err := io.WriteString(conn, shutdownRequest)
			require.NoError(t, err)
			select {
			case <-started:
			case <-time.After(lifecycleWait):
				t.Fatal("handler did not start")
			}
			done := make(chan struct{})
			go func() { srv.Close(); close(done) }()
			<-srv.stopc
			assert.False(t, svc.closed.Load())
			close(release)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
			select {
			case <-done:
			case <-time.After(lifecycleWait):
				t.Fatal("Close did not finish after the request")
			}
			assert.True(t, svc.closed.Load())
		})
	}
}

func TestCloseClosesHTTPKeepAlive(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	svc := &shutdownService{serve: func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}}
	srv, conn := startShutdownServer(t, false, svc, time.Second)
	reader := bufio.NewReader(conn)
	_, err := io.WriteString(conn, shutdownRequest)
	require.NoError(t, err)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.False(t, resp.Close, "the first response must allow connection reuse")
	srv.Close()
	_, err = io.WriteString(conn, shutdownRequest)
	if err == nil {
		_, err = http.ReadResponse(reader, nil)
	}
	require.Error(t, err)
	assert.Equal(t, int32(1), calls.Load())
}

func TestCloseCancelsHTTPAfterTimeout(t *testing.T) {
	t.Parallel()
	started, finished := make(chan struct{}), make(chan struct{})
	svc := &shutdownService{serve: func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(finished)
	}}
	const timeout = 50 * time.Millisecond
	srv, conn := startShutdownServer(t, false, svc, timeout)
	_, err := io.WriteString(conn, shutdownRequest)
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(lifecycleWait):
		t.Fatal("handler did not start")
	}
	start := time.Now()
	srv.Close()
	assert.GreaterOrEqual(t, time.Since(start), timeout)
	ctx, cancel := context.WithTimeout(t.Context(), lifecycleWait)
	defer cancel()
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("Close must cancel the active HTTP request")
	}
}
