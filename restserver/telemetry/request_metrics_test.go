package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
	withRole := func(role string, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, identity.WithTestIdentity(r, identity.NewIdentity(role, "user", "", nil, "", "", identity.MethodNone)))
		})
	}
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
	rm := NewRequestMetrics(reject(withRole("admin", NewRequestMetrics(h))))

	serve := func(h http.Handler, r *http.Request, status int) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, status, w.Code)
	}
	serve(rm, httptest.NewRequest(http.MethodDelete, "/api/users/1", nil), http.StatusNoContent)
	serve(rm, httptest.NewRequest(http.MethodGet, "/denied", nil), http.StatusUnauthorized)
	// an identity outside the outer handler labels requests that never
	// reach the inner one
	serve(withRole("client", rm), httptest.NewRequest(http.MethodGet, "/denied", nil), http.StatusUnauthorized)
	// an empty role reported by the inner handler is kept
	serve(NewRequestMetrics(withRole("", NewRequestMetrics(h))),
		httptest.NewRequest(http.MethodDelete, "/api/users/2", nil), http.StatusNoContent)
	// three levels: the innermost role wins
	serve(NewRequestMetrics(withRole("client", NewRequestMetrics(withRole("admin", NewRequestMetrics(h))))),
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
