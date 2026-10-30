package appinit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/appinit/config"
	"github.com/effective-security/porto/xhttp/limits"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// scrapeTimeout is the Timeouts.Handler of the slow scrape test.
	scrapeTimeout = 200 * time.Millisecond
	// scrapeMetric is the counter the fast registries expose.
	scrapeMetric = "appinit_test_scrapes_total"
)

// blockingCollector is a Collector whose Collect waits until release is
// closed.
type blockingCollector struct {
	release chan struct{}
}

func (c *blockingCollector) Describe(chan<- *prom.Desc) {}
func (c *blockingCollector) Collect(chan<- prom.Metric) { <-c.release }

// fastRegistry returns a registry with one counter.
func fastRegistry(t *testing.T) *prom.Registry {
	t.Helper()
	registry := prom.NewRegistry()
	require.NoError(t, registry.Register(prom.NewCounter(prom.CounterOpts{Name: scrapeMetric})))
	return registry
}

// TestPrometheusHandlerTimeout checks that Timeouts.Handler bounds a scrape:
// a collector slower than it is answered 503 within the timeout, while a
// fast scrape and a scrape without the timeout are served.
func TestPrometheusHandlerTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	blocking := prom.NewRegistry()
	require.NoError(t, blocking.Register(&blockingCollector{release: release}))

	tcases := []struct {
		name     string
		handler  time.Duration
		registry *prom.Registry
		code     int
		body     string
	}{
		{
			name:     "unset",
			registry: fastRegistry(t),
			code:     http.StatusOK,
			body:     scrapeMetric,
		},
		{
			name:     "fast scrape",
			handler:  time.Second,
			registry: fastRegistry(t),
			code:     http.StatusOK,
			body:     scrapeMetric,
		},
		{
			name:     "slow scrape",
			handler:  scrapeTimeout,
			registry: blocking,
			code:     http.StatusServiceUnavailable,
			body:     "Exceeded configured timeout",
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Prometheus{Timeouts: limits.Timeouts{Handler: tc.handler}}
			handler := prometheusHandler(cfg, tc.registry, tc.registry)
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			rec := httptest.NewRecorder()
			start := time.Now()
			handler.ServeHTTP(rec, req)
			elapsed := time.Since(start)
			assert.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.body)
			if tc.code == http.StatusServiceUnavailable {
				assert.GreaterOrEqual(t, elapsed, scrapeTimeout)
			}
			assert.Less(t, elapsed, time.Second)
		})
	}
}
