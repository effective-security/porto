package gserver

import (
	"net"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

// Bounds of the wait after a failed Accept; net/http uses the same values.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

// backoffListener waits after each failed Accept before returning the error,
// so that cmux, which retries temporary errors such as EMFILE at once, does
// not spin while the process is out of file descriptors. The wait doubles
// from minDelay to maxDelay and resets after a successful Accept; Close ends
// it early. Errors are returned unchanged, so cmux still decides whether to
// retry; an error wrapping net.ErrClosed is returned without waiting.
type backoffListener struct {
	net.Listener
	minDelay  time.Duration
	maxDelay  time.Duration
	closed    chan struct{}
	closeOnce sync.Once

	mu    sync.Mutex
	delay time.Duration
}

func newBackoffListener(l net.Listener) *backoffListener {
	return &backoffListener{
		Listener: l,
		minDelay: acceptBackoffMin,
		maxDelay: acceptBackoffMax,
		closed:   make(chan struct{}),
	}
}

// Accept returns the next connection of the wrapped listener, or its error
// after the backoff delay.
func (l *backoffListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.delay = 0
		l.mu.Unlock()
		return conn, nil
	}
	if errors.Is(err, net.ErrClosed) {
		return nil, err
	}

	delay := l.nextDelay()
	logger.KV(xlog.WARNING,
		"reason", "accept_failed",
		"address", l.Addr().String(),
		"retry_in", delay.String(),
		"err", err.Error(),
	)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-l.closed:
	}
	return nil, err
}

// Close ends a pending backoff wait and closes the wrapped listener.
func (l *backoffListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

func (l *backoffListener) nextDelay() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.delay = min(max(2*l.delay, l.minDelay), l.maxDelay)
	return l.delay
}
