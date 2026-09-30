package telemetry_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	controllerOK = "ok"
	hijackedBody = "hijacked"
	hijackedResp = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n" + hijackedBody

	requestTimeout = 10 * time.Second
)

var testLogger = xlog.NewPackageLogger("github.com/effective-security/porto/restserver", "telemetry_test")

// telemetryChain wraps h like restserver and gserver do: metrics outside the
// request logger, each with its own ResponseCapture.
func telemetryChain(h http.Handler) http.Handler {
	return telemetry.NewRequestMetrics(telemetry.NewRequestLogger(h, time.Millisecond, testLogger))
}

// serveChain serves one GET request through telemetryChain(h) on a real
// server and returns the status and body. It returns only after the chain
// has returned: a client can read a hijacked response while the logger and
// metrics still run, and httptest.Server.Close does not wait for hijacked
// connections.
func serveChain(t *testing.T, h http.Handler) (int, string) {
	t.Helper()
	done := make(chan struct{})
	chain := telemetryChain(h)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		chain.ServeHTTP(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(t.Context(), requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	res, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	select {
	case <-done:
	case <-ctx.Done():
		require.FailNow(t, "the handler chain did not return")
	}
	return res.StatusCode, string(body)
}

// unwrapOnly hides every optional interface of the wrapped writer except
// Unwrap, like a middleware writer that supports http.ResponseController.
type unwrapOnly struct {
	http.ResponseWriter
}

func (u unwrapOnly) Unwrap() http.ResponseWriter {
	return u.ResponseWriter
}

// basicWriter implements only http.ResponseWriter.
type basicWriter struct {
	header http.Header
}

func (b *basicWriter) Header() http.Header         { return b.header }
func (b *basicWriter) Write(p []byte) (int, error) { return len(p), nil }
func (b *basicWriter) WriteHeader(int)             {}

func TestResponseCapture_Unwrap(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	rc := telemetry.NewResponseCapture(w)
	assert.Same(t, w, rc.Unwrap())
}

func TestResponseCapture_ResponseController(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		deadline := time.Now().Add(time.Minute)
		for _, err := range []error{
			rc.SetReadDeadline(deadline),
			rc.SetWriteDeadline(deadline),
			rc.EnableFullDuplex(),
		} {
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		_, _ = io.WriteString(w, controllerOK)
		// A failed flush after the body has started is reported in it.
		if err := rc.Flush(); err != nil {
			_, _ = io.WriteString(w, err.Error())
		}
	})

	status, body := serveChain(t, h)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, controllerOK, body)
}

func TestResponseCapture_Hijack(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "not a hijacker", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString(hijackedResp)
		_ = brw.Flush()
	})

	status, body := serveChain(t, h)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, hijackedBody, body)
}

func TestResponseCapture_HijackNotSupported(t *testing.T) {
	t.Parallel()
	rc := telemetry.NewResponseCapture(httptest.NewRecorder())
	conn, brw, err := rc.Hijack()
	require.Error(t, err)
	assert.ErrorIs(t, err, http.ErrNotSupported)
	assert.Nil(t, conn)
	assert.Nil(t, brw)
}

func TestResponseCapture_Flush(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	rc := telemetry.NewResponseCapture(unwrapOnly{w})
	rc.Flush()
	assert.True(t, w.Flushed)

	w = httptest.NewRecorder()
	rc = telemetry.NewResponseCapture(unwrapOnly{w})
	require.NoError(t, http.NewResponseController(rc).Flush())
	assert.True(t, w.Flushed)

	// A delegate that cannot flush makes Flush a no-op, and FlushError
	// (used by http.ResponseController) reports it.
	bw := &basicWriter{header: http.Header{}}
	rc = telemetry.NewResponseCapture(bw)
	assert.NotPanics(t, rc.Flush)
	assert.ErrorIs(t, rc.FlushError(), http.ErrNotSupported)
	assert.ErrorIs(t, http.NewResponseController(rc).Flush(), http.ErrNotSupported)
	_, _, err := rc.Hijack()
	assert.ErrorIs(t, err, http.ErrNotSupported)
}
