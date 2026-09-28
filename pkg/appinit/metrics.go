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
// CloudWatch starts a publishing goroutine; the returned closer flushes it.
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
			closers = append(closers, &contextCloser{
				ctx: context.Background(),
			})
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
		if _, err = metrics.NewGlobal(mcfg, sink); err != nil {
			return nil, errors.WithMessage(err, "failed to initialize global metrics")
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
		go newCWSink.Run(context.Background())
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

// contextCloser flushes the CloudWatch sink on Close.
type contextCloser struct {
	ctx context.Context
}

// Close flushes the CloudWatch sink; it does not stop its Run goroutine.
func (c *contextCloser) Close() error {
	if cwSink != nil {
		err := cwSink.Flush(context.Background())
		if err != nil {
			logger.KV(xlog.ERROR, "reason", "metrics_flush", "err", err.Error())
		}
		logger.ContextKV(c.ctx, xlog.TRACE, "status", "sink_flushed")
	}
	logger.ContextKV(c.ctx, xlog.TRACE, "status", "metrics_closed")

	c.ctx.Done()
	return nil
}
