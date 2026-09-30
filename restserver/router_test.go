package restserver_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/effective-security/metrics"
	rest "github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	marshal.WriteJSON(w, r, httperror.NotFound("URL: %s", r.URL.Path))
}

type handler struct {
	methods    map[string]int
	parameters map[string]int
}

func (h *handler) handle(w http.ResponseWriter, r *http.Request, p rest.Params) {
	h.methods[r.Method]++
	pv := p.ByName(r.Method)
	if pv != "" {
		h.parameters[pv]++
	}
}

func Test_Router(t *testing.T) {
	router := rest.NewRouter(notFoundHandler)
	h := &handler{
		methods:    map[string]int{},
		parameters: map[string]int{},
	}
	router.GET("/get", h.handle)
	router.GET("/get/:GET", h.handle)
	router.HEAD("/head", h.handle)
	router.OPTIONS("/options", h.handle)
	router.POST("/post", h.handle)
	router.PUT("/put", h.handle)
	router.PATCH("/patch", h.handle)
	router.DELETE("/del", h.handle)
	router.CONNECT("/", h.handle)

	assert.Equal(t, 0, h.methods[http.MethodGet])
	assert.Equal(t, 0, h.methods[http.MethodHead])
	assert.Equal(t, 0, h.methods[http.MethodOptions])
	assert.Equal(t, 0, h.methods[http.MethodPost])
	assert.Equal(t, 0, h.methods[http.MethodPut])
	assert.Equal(t, 0, h.methods[http.MethodPatch])
	assert.Equal(t, 0, h.methods[http.MethodDelete])
	assert.Equal(t, 0, h.methods[http.MethodConnect])

	rh := router.Handler()
	assert.NotNil(t, rh)

	w := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/get/GET", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodGet])

	r, err = http.NewRequest(http.MethodHead, "/head", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodHead])

	r, err = http.NewRequest(http.MethodOptions, "/options", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodOptions])

	r, err = http.NewRequest(http.MethodPost, "/post", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodPost])

	r, err = http.NewRequest(http.MethodPatch, "/patch?OTHER", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodPatch])

	r, err = http.NewRequest(http.MethodDelete, "/del?DELETE", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodDelete])

	r, err = http.NewRequest(http.MethodConnect, "/", nil)
	require.NoError(t, err)
	rh.ServeHTTP(w, r)
	assert.Equal(t, 1, h.methods[http.MethodConnect])

	assert.Equal(t, 1, h.parameters["GET"])
	assert.Equal(t, 0, h.parameters["DELETE"])
	assert.Equal(t, 0, h.parameters["OTHER"])
}

// Test_RouterRouteMetrics checks that request metrics behind the Router are
// labelled by the registered route template, and that requests the Router
// answers itself (not found, 405, redirects) are labelled unknown. It
// installs a process-global metrics sink, so it must not run in parallel.
func Test_RouterRouteMetrics(t *testing.T) {
	im := metrics.NewInmemSink(time.Minute, 5*time.Minute)
	// Runtime metrics would add samples to the exact comparisons.
	mcfg := metrics.DefaultConfig("routertest")
	mcfg.EnableRuntimeMetrics = false
	_, err := metrics.NewGlobal(mcfg, im)
	require.NoError(t, err)

	ok := func(w http.ResponseWriter, _ *http.Request, _ rest.Params) {
		w.WriteHeader(http.StatusOK)
	}
	router := rest.NewRouter(notFoundHandler)
	router.GET("/v1/users/:id", ok)
	router.DELETE("/v1/users/:id", ok)
	router.GET("/v1/files/*path", ok)
	router.GET("/v1/static", ok)
	h := telemetry.NewRequestMetrics(router.Handler())

	tcases := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/v1/users/1", http.StatusOK},
		{http.MethodGet, "/v1/users/2", http.StatusOK},
		{http.MethodDelete, "/v1/users/3", http.StatusOK},
		{http.MethodGet, "/v1/files/a/b.txt", http.StatusOK},
		{http.MethodGet, "/v1/static", http.StatusOK},
		{http.MethodGet, "/v1/nope/1", http.StatusNotFound},
		{http.MethodGet, "/v1/nope/2", http.StatusNotFound},
		{http.MethodPost, "/v1/users/4", http.StatusMethodNotAllowed},
		{"FOO123", "/v1/users/5", http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/static/", http.StatusMovedPermanently},
	}
	for _, tc := range tcases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		assert.Equal(t, tc.status, w.Code, "%s %s", tc.method, tc.path)
	}

	counters := map[string]int{}
	for _, interval := range im.Data() {
		for k, v := range interval.Counters {
			counters[k] += v.Count
		}
	}
	assert.Equal(t, map[string]int{
		"routertest_http_requests_role;verb=GET;status=200;uri=/v1/users/:id;role=guest":    2,
		"routertest_http_requests_role;verb=DELETE;status=200;uri=/v1/users/:id;role=guest": 1,
		"routertest_http_requests_role;verb=GET;status=200;uri=/v1/files/*path;role=guest":  1,
		"routertest_http_requests_role;verb=GET;status=200;uri=/v1/static;role=guest":       1,
		"routertest_http_requests_role;verb=GET;status=404;uri=unknown;role=guest":          2,
		"routertest_http_requests_role;verb=POST;status=405;uri=unknown;role=guest":         1,
		"routertest_http_requests_role;verb=_OTHER;status=405;uri=unknown;role=guest":       1,
		"routertest_http_requests_role;verb=GET;status=301;uri=unknown;role=guest":          1,
	}, counters)
}
