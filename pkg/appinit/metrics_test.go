package appinit

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	metricsProm "github.com/effective-security/metrics/prometheus"
	"github.com/effective-security/porto/pkg/appinit/config"
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
