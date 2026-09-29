package gserver

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/soheilhy/cmux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const backoffTestWait = 5 * time.Second

// newEMFILE returns the error net.TCPListener.Accept reports when the
// process is out of file descriptors; cmux retries it.
func newEMFILE() error {
	return &net.OpError{
		Op:  "accept",
		Net: "tcp",
		Err: os.NewSyscallError("accept4", syscall.EMFILE),
	}
}

// scriptedListener returns the scripted results from Accept, then acceptErr
// for every later call; called receives one value per Accept call.
type scriptedListener struct {
	mu        sync.Mutex
	results   []error // nil means a connection
	acceptErr error
	called    chan struct{}
	calls     atomic.Int32
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	if l.called != nil {
		select {
		case l.called <- struct{}{}:
		default:
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.results) > 0 {
		err := l.results[0]
		l.results = l.results[1:]
		if err == nil {
			server, client := net.Pipe()
			_ = client.Close()
			return server, nil
		}
		return nil, err
	}
	return nil, l.acceptErr
}

func (l *scriptedListener) Close() error { return nil }

func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func TestBackoffListenerDelays(t *testing.T) {
	t.Parallel()

	emfile := newEMFILE()
	inner := &scriptedListener{
		results:   []error{emfile, emfile, emfile, nil},
		acceptErr: emfile,
	}
	l := newBackoffListener(inner)
	// Accept is exercised below with a short wait; the schedule is checked
	// on nextDelay directly.
	l.minDelay = time.Millisecond
	l.maxDelay = time.Millisecond

	for range 3 {
		conn, err := l.Accept()
		assert.Nil(t, conn)
		assert.Same(t, emfile, err, "the error is returned unchanged")
	}
	conn, err := l.Accept()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	l.mu.Lock()
	assert.Zero(t, l.delay, "a successful Accept resets the delay")
	l.mu.Unlock()

	l.minDelay = acceptBackoffMin
	l.maxDelay = acceptBackoffMax
	var got []time.Duration
	for range 10 {
		got = append(got, l.nextDelay())
	}
	assert.Equal(t, []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		80 * time.Millisecond,
		160 * time.Millisecond,
		320 * time.Millisecond,
		640 * time.Millisecond,
		time.Second,
		time.Second,
	}, got)
}

func TestBackoffListenerClosedErrorDoesNotWait(t *testing.T) {
	t.Parallel()

	closedErr := errors.Wrap(net.ErrClosed, "accept")
	l := newBackoffListener(&scriptedListener{acceptErr: closedErr})
	l.minDelay = time.Hour
	l.maxDelay = time.Hour

	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	select {
	case err := <-done:
		assert.Same(t, closedErr, err)
	case <-time.After(backoffTestWait):
		t.Fatal("Accept waited after a closed-listener error")
	}
	l.mu.Lock()
	assert.Zero(t, l.delay)
	l.mu.Unlock()
}

func TestBackoffListenerCloseEndsWait(t *testing.T) {
	t.Parallel()

	emfile := newEMFILE()
	inner := &scriptedListener{
		acceptErr: emfile,
		called:    make(chan struct{}, 1),
	}
	l := newBackoffListener(inner)
	l.minDelay = time.Hour
	l.maxDelay = time.Hour

	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	select {
	case <-inner.called:
	case <-time.After(backoffTestWait):
		t.Fatal("Accept did not call the wrapped listener")
	}
	require.NoError(t, l.Close())
	select {
	case err := <-done:
		assert.Same(t, emfile, err)
	case <-time.After(backoffTestWait):
		t.Fatal("Close did not end the backoff wait")
	}
	// A repeated Close does not panic.
	require.NoError(t, l.Close())
}

// failWindowListener fails Accept with EMFILE for window from its first
// Accept call, then delegates to the wrapped listener; failures counts the
// failed calls.
type failWindowListener struct {
	net.Listener
	window   time.Duration
	start    sync.Once
	until    time.Time
	failures atomic.Int32
}

func (l *failWindowListener) Accept() (net.Conn, error) {
	// cmux calls Accept from one goroutine, so until needs no lock after start.
	l.start.Do(func() { l.until = time.Now().Add(l.window) })
	if time.Now().Before(l.until) {
		l.failures.Add(1)
		return nil, newEMFILE()
	}
	return l.Listener.Accept()
}

// cmux retries EMFILE at once; behind backoffListener it waits between
// retries and serves again when descriptors are available.
func TestBackoffListenerPacesCMux(t *testing.T) {
	t.Parallel()

	const window = 300 * time.Millisecond
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	inner := &failWindowListener{Listener: raw, window: window}
	root := newBackoffListener(inner)

	m := cmux.New(root)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: backoffTestWait,
	}
	httpL := m.Match(cmux.HTTP1())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(httpL) }()
	muxed := make(chan error, 1)
	go func() { muxed <- m.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = root.Close()
		for _, c := range []chan error{served, muxed} {
			select {
			case <-c:
			case <-time.After(backoffTestWait):
				t.Error("server did not stop")
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), backoffTestWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+raw.Addr().String(), nil)
	require.NoError(t, err)
	res, err := (&http.Client{Timeout: backoffTestWait}).Do(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	assert.Equal(t, http.StatusOK, res.StatusCode)

	// Waits of 5, 10, 20, 40, 80 and 160ms cover the window in about 7
	// calls; without the backoff cmux calls Accept many thousand times.
	failures := inner.failures.Load()
	assert.Positive(t, failures)
	assert.LessOrEqual(t, failures, int32(20))
}

func TestConfigureListenersUsesBackoff(t *testing.T) {
	t.Parallel()

	// Short directory: t.TempDir can exceed the 104-byte socket path limit on macOS.
	dir, err := os.MkdirTemp("", "gs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "gs.sock")
	cfg := &Config{
		ListenURLs: []string{"http://127.0.0.1:0", "unix://" + sock},
	}
	sctxs, tlsInfo, err := configureListeners(cfg)
	require.NoError(t, err)
	assert.Nil(t, tlsInfo)
	require.Len(t, sctxs, 2)
	for addr, sctx := range sctxs {
		assert.IsType(t, &backoffListener{}, sctx.listener, addr)
		require.NoError(t, sctx.listener.Close())
		sctx.cancel()
	}
}
