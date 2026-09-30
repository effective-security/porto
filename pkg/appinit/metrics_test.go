package appinit

import (
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	metricsProm "github.com/effective-security/metrics/prometheus"
	pmetricskey "github.com/effective-security/porto/metricskey"
	"github.com/effective-security/porto/pkg/appinit/config"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/limits"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Metrics changes process globals, so these tests must not run in parallel.
func isolatePrometheus(t *testing.T) {
	t.Helper()
	oldSink, oldCWSink, oldRegisterer, oldGatherer := promSink, cwSink, prom.DefaultRegisterer, prom.DefaultGatherer
	registry := prom.NewRegistry()
	promSink, cwSink = nil, nil
	prom.DefaultRegisterer, prom.DefaultGatherer = registry, registry
	t.Cleanup(func() {
		promSink, cwSink, prom.DefaultRegisterer, prom.DefaultGatherer = oldSink, oldCWSink, oldRegisterer, oldGatherer
	})
}

func TestMetricsPrometheusLifecycle(t *testing.T) {
	isolatePrometheus(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()
	cfg := &config.Metrics{
		Provider:   "prometheus,inmem",
		Prometheus: &config.Prometheus{Addr: occupied.Addr().String()},
	}
	closer, err := Metrics(cfg, "test", "test", "v1", 1, nil)
	require.ErrorContains(t, err, "unable to listen for Prometheus")
	assert.Nil(t, closer)
	assert.Nil(t, promSink, "failed bind must not initialize a sink")
	require.NoError(t, occupied.Close())
	closer, err = Metrics(cfg, "test", "test", "v1", 1, nil)
	require.NoError(t, err)
	require.NotNil(t, closer)
	defer closer.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+cfg.Prometheus.Addr+"/metrics", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "version")
	require.NoError(t, closer.Close())
	require.NoError(t, closer.Close())
	rebound, err := net.Listen("tcp", cfg.Prometheus.Addr)
	require.NoError(t, err, "Close releases the bound address")
	require.NoError(t, rebound.Close())
}

func TestMetricsFailureReleasesListener(t *testing.T) {
	isolatePrometheus(t)
	_, err := metricsProm.NewSinkFrom(metricsProm.Opts{Registerer: prom.DefaultRegisterer})
	require.NoError(t, err)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := probe.Addr().String()
	require.NoError(t, probe.Close())
	closer, err := Metrics(&config.Metrics{
		Provider:   "prometheus",
		Prometheus: &config.Prometheus{Addr: addr},
	}, "test", "test", "v1", 1, nil)
	require.ErrorContains(t, err, "failed to create prometheus sink")
	assert.Nil(t, closer)
	probe, err = net.Listen("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, probe.Close())
}

func TestMetricsFailureReleasesCloudWatchSink(t *testing.T) {
	isolatePrometheus(t)
	// A conflicting registration makes the Prometheus sink fail after the
	// CloudWatch sink has been created.
	_, err := metricsProm.NewSinkFrom(metricsProm.Opts{Registerer: prom.DefaultRegisterer})
	require.NoError(t, err)
	closer, err := Metrics(&config.Metrics{
		Provider: "cloudwatch,prometheus",
		CloudWatch: &config.CloudWatch{
			AwsRegion: "us-west-2",
			Namespace: "test",
		},
		Prometheus: &config.Prometheus{},
	}, "test", "test", "v1", 1, nil)
	require.ErrorContains(t, err, "failed to create prometheus sink")
	assert.Nil(t, closer)
	assert.Nil(t, cwSink, "failed initialization must not keep the CloudWatch sink")
	assert.Nil(t, promSink)
}

// cloudWatchEndpoint is a fake CloudWatch endpoint that records the bodies
// of PutMetricData requests.
type cloudWatchEndpoint struct {
	mu     sync.Mutex
	bodies []string
}

func (e *cloudWatchEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body io.Reader = r.Body
	if r.Header.Get(header.ContentEncoding) == header.Gzip {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = gz
	}
	b, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/operation/PutMetricData") {
		e.mu.Lock()
		e.bodies = append(e.bodies, string(b))
		e.mu.Unlock()
	}
	// The SDK accepts an empty PutMetricData response.
	w.WriteHeader(http.StatusOK)
}

func (e *cloudWatchEndpoint) published() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.bodies)
}

// isolateAWSEnv gives the CloudWatch client static test credentials and no
// shared AWS configuration.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", missing)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "false")
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "false")
}

const (
	cloudWatchRunFrame = "cloudwatch.(*Sink).Run("
	collectStatsFrame  = "metrics.(*Metrics).collectStats("
)

// goroutinesIn counts the goroutines whose stack contains frame.
func goroutinesIn(frame string) int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), frame)
		}
		buf = make([]byte, 2*len(buf))
	}
}

// Close stops the CloudWatch publishing goroutine and returns after its
// final publish (P-067), and stops the runtime stats collector.
func TestMetricsCloudWatchCloseStopsRun(t *testing.T) {
	isolatePrometheus(t)
	isolateAWSEnv(t)
	endpoint := &cloudWatchEndpoint{}
	srv := httptest.NewServer(endpoint)
	defer srv.Close()

	runs, collectors := goroutinesIn(cloudWatchRunFrame), goroutinesIn(collectStatsFrame)
	closer, err := Metrics(&config.Metrics{
		Provider:             "cloudwatch",
		EnableRuntimeMetrics: true,
		CloudWatch: &config.CloudWatch{
			AwsRegion:   "us-west-2",
			AwsEndpoint: srv.URL,
			Namespace:   "porto-appinit-test",
			// The interval never elapses, so only the shutdown flush publishes.
			PublishInterval: time.Hour,
		},
	}, "test", "test", "v1", 1, nil)
	require.NoError(t, err)
	require.NotNil(t, closer)
	require.Eventually(t, func() bool {
		return goroutinesIn(cloudWatchRunFrame) == runs+1 && goroutinesIn(collectStatsFrame) == collectors+1
	}, 5*time.Second, time.Millisecond, "Run and the runtime stats collector start")
	assert.Empty(t, endpoint.published())

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { assert.NoError(t, closer.Close()) })
	}
	wg.Wait()
	// Close waits for Run to return, not for the collector to exit.
	assert.Equal(t, runs, goroutinesIn(cloudWatchRunFrame), "Close stops Run")
	assert.Eventually(t, func() bool {
		return goroutinesIn(collectStatsFrame) == collectors
	}, 5*time.Second, time.Millisecond, "Close stops the runtime stats collector")
	published := endpoint.published()
	require.Len(t, published, 1, "Close waits for the final publish")
	assert.Contains(t, published[0], "porto-appinit-test")
	assert.Contains(t, published[0], pmetricskey.StatsVersion.Name, "Metrics sets the version gauge")

	require.NoError(t, closer.Close())
	assert.Len(t, endpoint.published(), 1, "a repeated Close publishes nothing")
}

func TestMetricsRejectsProviderBeforeBinding(t *testing.T) {
	isolatePrometheus(t)
	for _, provider := range []string{"prometheus,invalid", "prometheus,prometheus", "prometheus,cloudwatch"} {
		closer, err := Metrics(&config.Metrics{
			Provider:   provider,
			Prometheus: &config.Prometheus{Addr: "invalid address"},
		}, "test", "test", "v1", 1, nil)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "unable to listen")
		assert.Nil(t, closer)
		assert.Nil(t, promSink)
	}
}

func TestPrometheusServerTimeoutAndConcurrentClose(t *testing.T) {
	t.Parallel()
	p, err := newPrometheusServer(&config.Prometheus{
		Addr:     "127.0.0.1:0",
		Timeouts: limits.Timeouts{Header: 100 * time.Millisecond},
	})
	require.NoError(t, err)
	p.start()
	defer p.Close()
	conn, err := net.DialTimeout("tcp", p.listener.Addr().String(), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = io.WriteString(conn, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
	require.NoError(t, err)
	_, err = io.ReadAll(conn)
	require.NoError(t, err, "server closes partial headers before client deadline")

	// Close overlaps active connections and other Close calls.
	conn, err = net.DialTimeout("tcp", p.listener.Addr().String(), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { assert.NoError(t, p.Close()) })
	}
	wg.Wait()
	_, err = io.ReadAll(conn)
	if err != nil {
		var ne net.Error
		require.True(t, errors.As(err, &ne))
		assert.False(t, ne.Timeout(), "connection must be closed rather than timing out")
	}
}
