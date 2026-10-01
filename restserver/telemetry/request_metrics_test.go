package telemetry

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/effective-security/metrics"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testMetricsPrefix = "test"
	usersRoute        = "/users/:id"
)

func Test_RequestMetricsStatusCode(t *testing.T) {
	t.Parallel()
	rm := NewRequestMetrics(nil).(*requestMetrics)

	assert.Equal(t, "200", rm.statusCode(200))
	assert.Equal(t, "500", rm.statusCode(500))
	assert.Equal(t, "700", rm.statusCode(700))
	assert.Equal(t, "0", rm.statusCode(0))
}

func Test_MethodLabel(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		method string
		exp    string
	}{
		{http.MethodGet, http.MethodGet},
		{http.MethodHead, http.MethodHead},
		{http.MethodPost, http.MethodPost},
		{http.MethodPut, http.MethodPut},
		{http.MethodPatch, http.MethodPatch},
		{http.MethodDelete, http.MethodDelete},
		{http.MethodConnect, http.MethodConnect},
		{http.MethodOptions, http.MethodOptions},
		{http.MethodTrace, http.MethodTrace},
		{"get", OtherMethod},
		{"FOO123", OtherMethod},
		{"PROPFIND", OtherMethod},
		{"", OtherMethod},
	}
	for _, tc := range tcases {
		assert.Equal(t, tc.exp, methodLabel(tc.method), tc.method)
	}
}

// newInmemMetrics installs a global in-memory metrics sink for the test.
// Tests that call it must not run in parallel: the sink is process-global.
func newInmemMetrics(t *testing.T) *metrics.InmemSink {
	im := metrics.NewInmemSink(time.Minute, time.Minute*5)
	// Runtime metrics would add samples to the exact comparisons.
	mcfg := metrics.DefaultConfig(testMetricsPrefix)
	mcfg.EnableRuntimeMetrics = false
	_, err := metrics.NewGlobal(mcfg, im)
	require.NoError(t, err)
	return im
}

// metricCounts returns the count of every sample and counter key, summed
// over all intervals so that a test crossing an interval boundary still
// sees every emission.
func metricCounts(im *metrics.InmemSink) (samples, counters map[string]int) {
	samples = map[string]int{}
	counters = map[string]int{}
	for _, interval := range im.Data() {
		for k, v := range interval.Samples {
			samples[k] += v.Count
		}
		for k, v := range interval.Counters {
			counters[k] += v.Count
		}
	}
	return samples, counters
}

func Test_RequestMetrics(t *testing.T) {
	im := newInmemMetrics(t)

	// The handler records usersRoute for /users/* like a router, and
	// answers every other path without recording a route.
	handlerStatusCode := http.StatusOK
	h := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/users/") {
			SetRoute(r.Context(), usersRoute)
		}
		w.WriteHeader(handlerStatusCode)
		_, _ = io.WriteString(w, `"Hello World"`)
	}
	rm := NewRequestMetrics(http.HandlerFunc(h))
	req := func(method, uri string, sc int) {
		r := httptest.NewRequest(method, uri, nil)
		r = identity.WithTestIdentity(r, identity.NewIdentity("admin", "10.0.0.1", "", nil, "", "", identity.MethodNone))

		w := httptest.NewRecorder()
		handlerStatusCode = sc
		rm.ServeHTTP(w, r)
		require.Equal(t, sc, w.Code)
	}
	req(http.MethodGet, "/users/1", http.StatusOK)
	req(http.MethodGet, "/users/2", http.StatusOK)
	req(http.MethodGet, "/users/3", http.StatusNotFound)
	req(http.MethodPost, "/users/4", http.StatusBadRequest)
	req("FOO123", "/users/5", http.StatusOK)
	req("BAR", "/users/6", http.StatusOK)
	req(http.MethodGet, "/", http.StatusOK)
	req(http.MethodPost, "/notfound/1", http.StatusNotFound)
	req(http.MethodPost, "/notfound/2", http.StatusNotFound)
	req(http.MethodGet, "/denied/xyz", http.StatusUnauthorized)
	req("FOO123", "/scan", http.StatusMethodNotAllowed)

	samples, counters := metricCounts(im)
	assert.Equal(t, map[string]int{
		"test_http_requests_perf;verb=GET;status=200;uri=/users/:id":    2,
		"test_http_requests_perf;verb=GET;status=404;uri=/users/:id":    1,
		"test_http_requests_perf;verb=POST;status=400;uri=/users/:id":   1,
		"test_http_requests_perf;verb=_OTHER;status=200;uri=/users/:id": 2,
		"test_http_requests_perf;verb=GET;status=200;uri=unknown":       1,
		"test_http_requests_perf;verb=POST;status=404;uri=unknown":      2,
		"test_http_requests_perf;verb=GET;status=401;uri=unknown":       1,
		"test_http_requests_perf;verb=_OTHER;status=405;uri=unknown":    1,
	}, samples)
	assert.Equal(t, map[string]int{
		"test_http_requests_role;verb=GET;status=200;uri=/users/:id;role=admin":    2,
		"test_http_requests_role;verb=GET;status=404;uri=/users/:id;role=admin":    1,
		"test_http_requests_role;verb=POST;status=400;uri=/users/:id;role=admin":   1,
		"test_http_requests_role;verb=_OTHER;status=200;uri=/users/:id;role=admin": 2,
		"test_http_requests_role;verb=GET;status=200;uri=unknown;role=admin":       1,
		"test_http_requests_role;verb=POST;status=404;uri=unknown;role=admin":      2,
		"test_http_requests_role;verb=GET;status=401;uri=unknown;role=admin":       1,
		"test_http_requests_role;verb=_OTHER;status=405;uri=unknown;role=admin":    1,
	}, counters)
}

func Test_RequestMetricsNested(t *testing.T) {
	im := newInmemMetrics(t)

	// Both metrics handlers share one label holder, so the outer one sees
	// the route recorded behind the inner one (the last SetRoute wins) and
	// the role of the identity the inner one saw; only the outer records.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetRoute(r.Context(), "/api/*rest")
		SetRoute(r.Context(), usersRoute)
		w.WriteHeader(http.StatusNoContent)
	})
	// identity rejects requests to /denied before the inner handler
	reject := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/denied") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	rm := NewRequestMetrics(reject(withTestRole("admin", NewRequestMetrics(h))))

	serve := func(h http.Handler, r *http.Request, status int) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, status, w.Code)
	}
	serve(rm, httptest.NewRequest(http.MethodDelete, "/api/users/1", nil), http.StatusNoContent)
	serve(rm, httptest.NewRequest(http.MethodGet, "/denied", nil), http.StatusUnauthorized)
	// an identity outside the outer handler labels requests that never
	// reach the inner one
	serve(withTestRole("client", rm), httptest.NewRequest(http.MethodGet, "/denied", nil), http.StatusUnauthorized)
	// an empty role reported by the inner handler is kept
	serve(NewRequestMetrics(withTestRole("", NewRequestMetrics(h))),
		httptest.NewRequest(http.MethodDelete, "/api/users/2", nil), http.StatusNoContent)
	// three levels: the innermost role wins
	serve(NewRequestMetrics(withTestRole("client", NewRequestMetrics(withTestRole("admin", NewRequestMetrics(h))))),
		httptest.NewRequest(http.MethodDelete, "/api/users/3", nil), http.StatusNoContent)

	samples, counters := metricCounts(im)
	assert.Equal(t, map[string]int{
		"test_http_requests_perf;verb=DELETE;status=204;uri=/users/:id": 3,
		"test_http_requests_perf;verb=GET;status=401;uri=unknown":       2,
	}, samples)
	assert.Equal(t, map[string]int{
		"test_http_requests_role;verb=DELETE;status=204;uri=/users/:id;role=admin": 2,
		"test_http_requests_role;verb=DELETE;status=204;uri=/users/:id;role=":      1,
		"test_http_requests_role;verb=GET;status=401;uri=unknown;role=guest":       1,
		"test_http_requests_role;verb=GET;status=401;uri=unknown;role=client":      1,
	}, counters)
}

// Test_RequestMetricsTimeoutRace records a route from a handler that
// http.TimeoutHandler left running after the metrics handler returned, so
// the route writes overlap the metrics read; run with -race.
func Test_RequestMetricsTimeoutRace(t *testing.T) {
	im := newInmemMetrics(t)

	const requests = 10
	for range requests {
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer wg.Done()
			for {
				SetRoute(r.Context(), usersRoute)
				select {
				case <-stop:
					return
				default:
				}
			}
		})
		rm := NewRequestMetrics(http.TimeoutHandler(slow, time.Millisecond, "timeout"))

		w := httptest.NewRecorder()
		rm.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users/1", nil))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		close(stop)
		wg.Wait()
	}

	// The slow handler usually records its route before the timeout, but
	// may not have started yet.
	_, counters := metricCounts(im)
	total := 0
	for k, v := range counters {
		assert.Contains(t, []string{
			"test_http_requests_role;verb=GET;status=503;uri=/users/:id;role=guest",
			"test_http_requests_role;verb=GET;status=503;uri=unknown;role=guest",
		}, k)
		total += v
	}
	assert.Equal(t, requests, total)
}

func Test_SetRouteWithoutMetrics(t *testing.T) {
	t.Parallel()
	// No holder in the context: SetRoute is a no-op.
	r := httptest.NewRequest(http.MethodGet, "/users/1", nil)
	assert.NotPanics(t, func() {
		SetRoute(r.Context(), usersRoute)
	})
	assert.Nil(t, r.Context().Value(labelsKey{}))
}

// Test_RequestMetricsPanic checks that a request whose handler panics is
// recorded once, with its route and role, and with the status it sent or
// 500 when it sent none, and that the panic continues unchanged (formerly
// P-091). http.ErrAbortHandler is counted like any other panic.
func Test_RequestMetricsPanic(t *testing.T) {
	im := newInmemMetrics(t)

	errBoom := errors.New("boom")
	flush := func(w http.ResponseWriter) { w.(http.Flusher).Flush() }
	tcases := []struct {
		route  string
		value  any
		write  func(w http.ResponseWriter)
		writer http.ResponseWriter
	}{
		{"/none", errBoom, func(http.ResponseWriter) {}, nil},
		{"/status", errBoom, func(w http.ResponseWriter) { w.WriteHeader(http.StatusAccepted) }, nil},
		{"/body", "boom", func(w http.ResponseWriter) { _, _ = io.WriteString(w, "partial") }, nil},
		{"/flush", errBoom, flush, nil},
		// a flush that no writer in the chain supports sends nothing
		{"/flush-unsupported", errBoom, flush, plainWriter{http.Header{}}},
		{"/informational", errBoom, func(w http.ResponseWriter) { w.WriteHeader(http.StatusEarlyHints) }, nil},
		// net/http (and httptest) panic on an invalid code
		{"/invalid-status", "invalid WriteHeader code 0", func(w http.ResponseWriter) { w.WriteHeader(0) }, nil},
		{"/abort", http.ErrAbortHandler, func(http.ResponseWriter) {}, nil},
		{"/abort-status", http.ErrAbortHandler, func(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }, nil},
	}
	for _, tc := range tcases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			SetRoute(r.Context(), tc.route)
			tc.write(w)
			panic(tc.value)
		})
		// the nested handler reports the role, as in both servers
		rm := NewRequestMetrics(withTestRole("admin", NewRequestMetrics(h)))
		w := tc.writer
		if w == nil {
			w = httptest.NewRecorder()
		}
		assert.PanicsWithValue(t, tc.value, func() {
			rm.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.route, nil))
		}, tc.route)
	}

	// runtime.Goexit also leaves the handler without returning
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewRequestMetrics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			SetRoute(r.Context(), "/goexit")
			runtime.Goexit()
		})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/goexit", nil))
	}()
	<-done

	samples, counters := metricCounts(im)
	assert.Equal(t, map[string]int{
		"test_http_requests_perf;verb=GET;status=500;uri=/none":              1,
		"test_http_requests_perf;verb=GET;status=202;uri=/status":            1,
		"test_http_requests_perf;verb=GET;status=200;uri=/body":              1,
		"test_http_requests_perf;verb=GET;status=200;uri=/flush":             1,
		"test_http_requests_perf;verb=GET;status=500;uri=/flush-unsupported": 1,
		"test_http_requests_perf;verb=GET;status=500;uri=/informational":     1,
		"test_http_requests_perf;verb=GET;status=500;uri=/invalid-status":    1,
		"test_http_requests_perf;verb=GET;status=500;uri=/abort":             1,
		"test_http_requests_perf;verb=GET;status=204;uri=/abort-status":      1,
		"test_http_requests_perf;verb=GET;status=500;uri=/goexit":            1,
	}, samples)
	assert.Equal(t, map[string]int{
		"test_http_requests_role;verb=GET;status=500;uri=/none;role=admin":              1,
		"test_http_requests_role;verb=GET;status=202;uri=/status;role=admin":            1,
		"test_http_requests_role;verb=GET;status=200;uri=/body;role=admin":              1,
		"test_http_requests_role;verb=GET;status=200;uri=/flush;role=admin":             1,
		"test_http_requests_role;verb=GET;status=500;uri=/flush-unsupported;role=admin": 1,
		"test_http_requests_role;verb=GET;status=500;uri=/informational;role=admin":     1,
		"test_http_requests_role;verb=GET;status=500;uri=/invalid-status;role=admin":    1,
		"test_http_requests_role;verb=GET;status=500;uri=/abort;role=admin":             1,
		"test_http_requests_role;verb=GET;status=204;uri=/abort-status;role=admin":      1,
		"test_http_requests_role;verb=GET;status=500;uri=/goexit;role=guest":            1,
	}, counters)
}

// crashHandler panics; Test_RequestMetricsPanicServer finds its name in the
// stack the server logs.
func crashHandler(http.ResponseWriter, *http.Request) {
	panic("crash")
}

// lockedBuffer is a bytes.Buffer safe for the server's error log and the
// test reading it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Test_RequestMetricsPanicServer serves panicking handlers with net/http:
// each request is counted as 500, and the panic still reaches the server,
// which aborts the response and logs the stack of the panicking handler
// (silently for http.ErrAbortHandler).
func Test_RequestMetricsPanicServer(t *testing.T) {
	im := newInmemMetrics(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/crash", crashHandler)
	mux.HandleFunc("/abort", func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	})
	errLog := &lockedBuffer{}
	srv := httptest.NewUnstartedServer(NewRequestMetrics(mux))
	srv.Config.ErrorLog = log.New(errLog, "", 0)
	srv.Start()
	defer srv.Close()

	// fresh connections, so the client never retries a request
	client := srv.Client()
	client.Transport.(*http.Transport).DisableKeepAlives = true
	for _, path := range []string{"/crash", "/abort"} {
		res, err := client.Get(srv.URL + path)
		if err == nil {
			_ = res.Body.Close()
		}
		require.Error(t, err, path)
	}

	// the server logs the panic before it closes the connection
	logged := errLog.String()
	assert.Contains(t, logged, "http: panic serving")
	assert.Contains(t, logged, "telemetry.crashHandler")
	assert.NotContains(t, logged, http.ErrAbortHandler.Error())

	_, counters := metricCounts(im)
	assert.Equal(t, map[string]int{
		"test_http_requests_role;verb=GET;status=500;uri=unknown;role=guest": 2,
	}, counters)
}

// plainWriter is a ResponseWriter without optional interfaces.
type plainWriter struct {
	header http.Header
}

func (w plainWriter) Header() http.Header         { return w.header }
func (w plainWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w plainWriter) WriteHeader(int)             {}

// withTestRole serves next with an identity of role.
func withTestRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, identity.WithTestIdentity(r, identity.NewIdentity(role, "user", "", nil, "", "", identity.MethodNone)))
	})
}
