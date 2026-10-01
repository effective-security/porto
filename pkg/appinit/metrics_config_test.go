package appinit

import (
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/effective-security/metrics/cloudwatch"
	metricsProm "github.com/effective-security/metrics/prometheus"
	pmetricskey "github.com/effective-security/porto/metricskey"
	"github.com/effective-security/porto/pkg/appinit/config"
	"github.com/effective-security/xlog"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Metrics changes process globals, so these tests must not run in parallel.

func TestMetricsDisabledIsNoop(t *testing.T) {
	disabled := true
	tcases := []struct {
		name string
		cfg  *config.Metrics
	}{
		{name: "nil config"},
		{name: "no provider", cfg: &config.Metrics{}},
		{
			name: "disabled",
			cfg: &config.Metrics{
				Disabled:   &disabled,
				Provider:   "prometheus,cloudwatch",
				Prometheus: &config.Prometheus{Addr: "invalid address"},
			},
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			isolatePrometheus(t)
			closer, err := Metrics(tc.cfg, "test", "test", "v1", 1, nil)
			require.NoError(t, err)
			assert.Nil(t, closer)
			assert.Nil(t, promSink, "no sink is created")
			assert.Nil(t, cwSink, "no sink is created")
		})
	}
}

func TestMetricsProviderValidation(t *testing.T) {
	tcases := []struct {
		name     string
		cfg      *config.Metrics
		cwSet    bool
		err      string
		noCloser bool
	}{
		{
			name: "prometheus without section",
			cfg:  &config.Metrics{Provider: "prometheus"},
			err:  "metrics: provider prometheus requires the prometheus config section",
		},
		{
			name: "cloudwatch without section",
			cfg:  &config.Metrics{Provider: "cloudwatch"},
			err:  "metrics: provider cloudwatch requires the cloudwatch config section",
		},
		{
			name: "cloudwatch twice",
			cfg: &config.Metrics{
				Provider:   "cloudwatch,cloudwatch",
				CloudWatch: &config.CloudWatch{AwsRegion: "us-west-2"},
			},
			err: "cloudwatch sink already initialized",
		},
		{
			name: "cloudwatch already initialized",
			cfg: &config.Metrics{
				Provider:   "cloudwatch",
				CloudWatch: &config.CloudWatch{AwsRegion: "us-west-2"},
			},
			cwSet: true,
			err:   "cloudwatch sink already initialized",
		},
		{
			name: "unknown provider",
			cfg:  &config.Metrics{Provider: "inmem,statsd"},
			err:  `metrics provider "statsd" not supported`,
		},
		{
			// in-memory providers need no sink and nothing to close
			name: "inmem only",
			cfg:  &config.Metrics{Provider: "inmem,inmemory"},
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			isolatePrometheus(t)
			var existing *cloudwatch.Sink
			if tc.cwSet {
				existing = &cloudwatch.Sink{}
				cwSink = existing
			}
			closer, err := Metrics(tc.cfg, "test", "test", "v1", 1, nil)
			if tc.err != "" {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			} else {
				require.NoError(t, err)
			}
			assert.Nil(t, closer)
			assert.Nil(t, promSink)
			assert.Same(t, existing, cwSink, "a rejected call keeps the sinks")
		})
	}
}

// gaugeLabels returns the label pairs and value of the gauge named name in
// the default Prometheus gatherer.
func gaugeLabels(t *testing.T, name string) (map[string]string, float64) {
	t.Helper()
	families, err := prom.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		require.Len(t, f.GetMetric(), 1)
		m := f.GetMetric()[0]
		require.NotNil(t, m.GetGauge(), "%s is a gauge", name)
		labels := make(map[string]string)
		for _, l := range m.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		return labels, m.GetGauge().GetValue()
	}
	require.Failf(t, "gauge not found", "%s", name)
	return nil, 0
}

func TestMetricsGlobalTags(t *testing.T) {
	tcases := []struct {
		name     string
		nodeName string
		want     map[string]string
	}{
		{
			name:     "all tags",
			nodeName: "node-1",
			want: map[string]string{
				"service":    "svc",
				"cluster_id": "cluster",
				"node":       "node-1",
			},
		},
		{
			// node is omitted when NODE_NAME is not set
			name: "without node name",
			want: map[string]string{
				"service":    "svc",
				"cluster_id": "cluster",
			},
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			isolatePrometheus(t)
			t.Setenv("NODE_NAME", tc.nodeName)
			closer, err := Metrics(&config.Metrics{
				Provider:   "prometheus",
				Prometheus: &config.Prometheus{},
				GlobalTags: []string{"service", "cluster_id", "node", "unsupported"},
			}, "svc", "cluster", "v1", 42, nil)
			require.NoError(t, err)
			assert.Nil(t, closer, "a Prometheus sink without an address needs no closer")

			labels, value := gaugeLabels(t, pmetricskey.StatsVersion.Name)
			assert.Equal(t, tc.want, labels)
			assert.Equal(t, float64(42), value)
		})
	}
}

// With both sinks configured, Metrics fans out to Prometheus and
// CloudWatch.
func TestMetricsPrometheusAndCloudWatch(t *testing.T) {
	isolatePrometheus(t)
	isolateAWSEnv(t)
	endpoint := &cloudWatchEndpoint{}
	srv := httptest.NewServer(endpoint)
	defer srv.Close()

	closer, err := Metrics(&config.Metrics{
		Provider:   "prometheus,cloudwatch",
		Prometheus: &config.Prometheus{},
		CloudWatch: &config.CloudWatch{
			AwsRegion:   "us-west-2",
			AwsEndpoint: srv.URL,
			Namespace:   "porto-appinit-fanout",
			// The interval never elapses, so only the shutdown flush publishes.
			PublishInterval: time.Hour,
		},
	}, "svc", "cluster", "v1", 7, nil)
	require.NoError(t, err)
	require.NotNil(t, closer)
	assert.NotNil(t, promSink)
	assert.NotNil(t, cwSink)

	_, value := gaugeLabels(t, pmetricskey.StatsVersion.Name)
	assert.Equal(t, float64(7), value, "the Prometheus sink receives the gauge")

	require.NoError(t, closer.Close())
	published := endpoint.published()
	require.Len(t, published, 1)
	assert.Contains(t, published[0], "porto-appinit-fanout")
	assert.Contains(t, published[0], pmetricskey.StatsVersion.Name, "the CloudWatch sink receives the gauge")
}

// A CloudWatch sink that cannot be created rolls back the Prometheus sink
// and endpoint created before it, so the call can be retried.
func TestMetricsCloudWatchFailureReleasesPrometheus(t *testing.T) {
	isolatePrometheus(t)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := probe.Addr().String()
	require.NoError(t, probe.Close())

	closer, err := Metrics(&config.Metrics{
		Provider:   "prometheus,cloudwatch",
		Prometheus: &config.Prometheus{Addr: addr},
		CloudWatch: &config.CloudWatch{AwsRegion: "us-west-2"},
	}, "test", "test", "v1", 1, nil)
	require.Error(t, err)
	assert.Equal(t, "failed to create cloudwatch sink: CloudWatchNamespace required", err.Error())
	assert.Nil(t, closer)
	assert.Nil(t, promSink)
	assert.Nil(t, cwSink)

	// the Prometheus sink was unregistered, so a new one registers again
	_, err = metricsProm.NewSinkFrom(metricsProm.Opts{Registerer: prom.DefaultRegisterer})
	require.NoError(t, err)
	probe, err = net.Listen("tcp", addr)
	require.NoError(t, err, "the endpoint released its address")
	require.NoError(t, probe.Close())
}

// Logs is not parallel: it replaces the process-global log formatter.
func TestLogsRotateFailure(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notDir, []byte("x"), 0600))

	before := xlog.GetFormatter()
	closer, err := Logs(&LogConfig{LogDir: notDir}, "test")
	require.ErrorIs(t, err, syscall.ENOTDIR)
	// the cause's text after the prefix is the OS error message
	prefix := "failed to initialize log rotate: unable to create log directory " + notDir + ": mkdir " + notDir + ": "
	assert.True(t, strings.HasPrefix(err.Error(), prefix), "%q has prefix %q", err.Error(), prefix)
	assert.Nil(t, closer)
	assert.True(t, before == xlog.GetFormatter(), "a failed rotation keeps the formatter")
}
