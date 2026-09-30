package appinit

import (
	"context"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/metrics"
	"github.com/effective-security/metrics/cloudwatch"
	"github.com/effective-security/metrics/prometheus"
	pmetricskey "github.com/effective-security/porto/metricskey"
	"github.com/effective-security/porto/pkg/appinit/config"
	"github.com/effective-security/xlog"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Sinks can be initialized only once per process; kept global for tests.
var (
	promSink metrics.Sink
	cwSink   *cloudwatch.Sink
)

// Metrics initializes the global metrics pipeline from cfg. Provider is a
// comma-separated list of "prometheus", "cloudwatch" and "inmem"; an empty
// provider or Disabled=true is a no-op returning (nil, nil). Prometheus
// registers with the default registry and, when Prometheus.Addr is set,
// binds synchronously and serves promhttp with bounded HTTP read deadlines.
// Bind errors are returned; unexpected serve errors are logged. The returned
// closer stops the HTTP endpoint, including active connections.
// CloudWatch starts a publishing goroutine; the returned closer stops it and
// waits for its final publish. With a Prometheus or CloudWatch sink,
// EnableRuntimeMetrics starts a runtime stats collector; the returned closer
// signals it to stop.
// GlobalTags accepts "service", "cluster_id" and "node" (from $NODE_NAME).
// describe lists the caller's metric descriptors, merged with metricskey.Metrics
// for Prometheus help text. It returns an error if a sink is already
// initialized or a provider is unknown.
func Metrics(cfg *config.Metrics, svcName, clusterName string, version string, commitNumber int, describe []*metrics.Describe) (closer io.Closer, err error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.Provider == "" || cfg.GetDisabled() {
		logger.KV(xlog.INFO,
			"status", "metrics_disabled",
			"version", version,
			"commit", commitNumber,
			"provider", cfg.Provider,
		)
		return nil, nil
	}

	var sinks []metrics.Sink
	var closers metricsClosers
	providers := strings.Split(cfg.Provider, ",")
	if err := validateMetricsProviders(cfg, providers); err != nil {
		return nil, err
	}
	var endpoint *prometheusServer
	var newPromSink *prometheus.Sink
	var newCWSink *cloudwatch.Sink
	if slices.Contains(providers, "prometheus") && cfg.Prometheus.Addr != "" {
		endpoint, err = newPrometheusServer(cfg.Prometheus)
		if err != nil {
			return nil, err
		}
		closers = append(closers, endpoint)
	}
	// Roll back every sink created by this call so a failed call can be retried.
	defer func() {
		if err != nil {
			if endpoint != nil {
				err = errors.CombineErrors(err, endpoint.Close())
			}
			if newPromSink != nil {
				prom.Unregister(newPromSink)
				promSink = nil
			}
			if newCWSink != nil {
				cwSink = nil
			}
		}
	}()

	mcfg := &metrics.Config{
		EnableHostname:       false,
		EnableHostnameLabel:  false, // added in GlobalTags
		EnableServiceLabel:   false, // added in GlobalTags
		FilterDefault:        true,
		EnableRuntimeMetrics: cfg.EnableRuntimeMetrics,
		TimerGranularity:     time.Millisecond,
		ProfileInterval:      time.Second,
		GlobalPrefix:         cfg.Prefix,
		AllowedPrefixes:      cfg.AllowedPrefixes,
		BlockedPrefixes:      cfg.BlockedPrefixes,
		NumberLabelPrefix:    cfg.PrefixForNumberLabels,
	}

	for _, tag := range cfg.GlobalTags {
		switch tag {
		case "service":
			mcfg.GlobalTags = append(mcfg.GlobalTags, metrics.Tag{Name: tag, Value: svcName})
		case "cluster_id":
			mcfg.GlobalTags = append(mcfg.GlobalTags, metrics.Tag{Name: tag, Value: clusterName})
		case "node":
			if nn := os.Getenv("NODE_NAME"); nn != "" {
				mcfg.GlobalTags = append(mcfg.GlobalTags, metrics.Tag{Name: tag, Value: nn})
			}
		}
	}

	for _, p := range providers {
		switch p {
		case "prometheus":
			// Remove Go collector
			prom.Unregister(collectors.NewGoCollector())
			prom.Unregister(collectors.NewBuildInfoCollector())
			prom.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

			ops := prometheus.Opts{
				Expiration: cfg.Prometheus.Expiration,
				Registerer: prom.DefaultRegisterer,
				Help:       mcfg.Help(describe, pmetricskey.Metrics),
			}

			newPromSink, err = prometheus.NewSinkFrom(ops)
			if err != nil {
				return nil, errors.WithMessage(err, "failed to create prometheus sink")
			}
			promSink = newPromSink
			sinks = append(sinks, promSink)

		case "cloudwatch":
			c := cloudwatch.Config{
				AwsRegion:       cfg.CloudWatch.AwsRegion,
				AwsEndpoint:     cfg.CloudWatch.AwsEndpoint,
				Namespace:       cfg.CloudWatch.Namespace,
				PublishInterval: cfg.CloudWatch.PublishInterval,
				WithSampleCount: cfg.CloudWatch.WithSampleCount,
				WithCleanup:     true, // reset after each Flush
			}

			newCWSink, err = cloudwatch.NewSink(&c)
			if err != nil {
				return nil, errors.WithMessage(err, "failed to create cloudwatch sink")
			}
			cwSink = newCWSink
			sinks = append(sinks, cwSink)
		}
		// "inmem", "inmemory" and "" need no sink; validateMetricsProviders
		// has already rejected unknown providers.
	}
	var sink metrics.Sink

	if len(sinks) == 1 {
		sink = sinks[0]
	} else if len(sinks) > 1 {
		sink = metrics.NewFanoutSink(sinks...)
	}

	if sink != nil {
		var global *metrics.Metrics
		if global, err = metrics.NewGlobal(mcfg, sink); err != nil {
			return nil, errors.WithMessage(err, "failed to initialize global metrics")
		}
		if cfg.EnableRuntimeMetrics {
			// Signal the runtime collector to stop before the CloudWatch
			// runner publishes the last interval; Close does not wait for
			// the collector to exit.
			closers = append(closers, runtimeStatsCloser{metrics: global})
		}
		pmetricskey.StatsVersion.SetGauge(float64(commitNumber))
	}

	xlog.OnError(func(pkg string) {
		pmetricskey.HealthLogErrors.IncrCounter(1, pkg, version)
	})

	logger.KV(xlog.INFO,
		"status", "metrics_started",
		"version", version,
		"commit", commitNumber,
		"provider", cfg.Provider,
		"tags", mcfg.GlobalTags,
	)

	// Start background work only after every fallible step has succeeded.
	if newCWSink != nil {
		closers = append(closers, startCloudWatch(newCWSink))
	}
	if endpoint != nil {
		endpoint.start()
	}
	if len(closers) > 0 {
		closer = closers
	}
	return closer, nil
}

// Validate all provider choices before binding or registering any sink.
func validateMetricsProviders(cfg *config.Metrics, providers []string) error {
	seen := make(map[string]bool)
	for _, p := range providers {
		switch p {
		case "prometheus":
			if promSink != nil || seen[p] {
				return errors.New("prometheus sink already initialized")
			}
			if cfg.Prometheus == nil {
				return errors.New("metrics: provider prometheus requires the prometheus config section")
			}
		case "cloudwatch":
			if cwSink != nil || seen[p] {
				return errors.New("cloudwatch sink already initialized")
			}
			if cfg.CloudWatch == nil {
				return errors.New("metrics: provider cloudwatch requires the cloudwatch config section")
			}
		case "inmem", "inmemory", "":
		default:
			return errors.Errorf("metrics provider %q not supported", p)
		}
		seen[p] = true
	}
	return nil
}

type metricsClosers []io.Closer

func (c metricsClosers) Close() error {
	var err error
	for _, closer := range c {
		err = errors.CombineErrors(err, closer.Close())
	}
	return err
}

// cloudWatchRunner owns the goroutine running the CloudWatch sink's
// publishing loop.
type cloudWatchRunner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// startCloudWatch runs sink.Run on a new goroutine until Close.
func startCloudWatch(sink *cloudwatch.Sink) *cloudWatchRunner {
	ctx, cancel := context.WithCancel(context.Background())
	r := &cloudWatchRunner{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(r.done)
		sink.Run(ctx)
	}()
	return r
}

// Close cancels the publishing loop and waits for Run to return. Run
// publishes the metrics of the last interval before it returns, bounded by
// the sink's shutdown timeout, and logs a failed publish. The metrics of an
// interval are lost when the cancellation aborts a periodic publish in
// flight, or meets a tick that Run has not handled yet (Run then publishes
// with the cancelled context). When Run already stopped on expired or
// missing credentials, Close returns at once without publishing. Close is
// idempotent and safe for concurrent use; it always returns nil.
func (r *cloudWatchRunner) Close() error {
	r.cancel()
	<-r.done
	return nil
}

// runtimeStatsCloser stops the runtime stats collector of the global
// metrics instance; emission through it keeps working.
type runtimeStatsCloser struct {
	metrics *metrics.Metrics
}

// Close signals the collector to stop without waiting for it to exit; it is
// idempotent and always returns nil.
func (c runtimeStatsCloser) Close() error {
	c.metrics.Close()
	return nil
}
