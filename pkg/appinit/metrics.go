package appinit

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/effective-security/metrics"
	"github.com/effective-security/metrics/cloudwatch"
	"github.com/effective-security/metrics/prometheus"
	pmetricskey "github.com/effective-security/porto/metricskey"
	"github.com/effective-security/porto/pkg/appinit/config"
	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// can be initialized only once per process.
// keep global for tests
var (
	promSink metrics.Sink
	cwSink   *cloudwatch.Sink
)

// Metrics initializer
func Metrics(cfg *config.Metrics, svcName, clusterName string, version string, commitNumber int, describe []*metrics.Describe) (io.Closer, error) {
	var err error
	var sink metrics.Sink
	var closer io.Closer

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

	switch cfg.Provider {
	case "":
		return nil, nil

	case "prometheus":
		if promSink == nil {
			// Remove Go collector
			prom.Unregister(collectors.NewGoCollector())
			prom.Unregister(collectors.NewBuildInfoCollector())
			prom.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

			ops := prometheus.Opts{
				Expiration: cfg.Prometheus.Expiration,
				Registerer: prom.DefaultRegisterer,
				Help:       mcfg.Help(describe, pmetricskey.Metrics),
			}

			promSink, err = prometheus.NewSinkFrom(ops)
			if err != nil {
				return nil, nil
			}

			if cfg.Prometheus != nil && cfg.Prometheus.Addr != "" {
				go func() {
					logger.KV(xlog.INFO, "status", "starting_metrics", "endpoint", cfg.Prometheus.Addr)
					// remove Prom metrics
					h := promhttp.HandlerFor(prom.DefaultGatherer, promhttp.HandlerOpts{})
					logger.Fatal(http.ListenAndServe(cfg.Prometheus.Addr, h).Error())
				}()
			}
		}
		sink = promSink

	case "cloudwatch":
		c := cloudwatch.Config{
			AwsRegion:       cfg.CloudWatch.AwsRegion,
			Namespace:       cfg.CloudWatch.Namespace,
			PublishInterval: cfg.CloudWatch.PublishInterval,
			PublishTimeout:  cfg.CloudWatch.PublishTimeout,
			WithSampleCount: cfg.CloudWatch.WithSampleCount,
			Validate:        false,
			WithCleanup:     true, // reset after each Flush
		}

		cwSink, err = cloudwatch.NewSink(&c)
		if err != nil {
			return nil, err
		}

		ctxcloser := &contextCloser{
			ctx: context.Background(),
		}

		go cwSink.Run(ctxcloser.ctx)
		sink = cwSink
		closer = ctxcloser

	case "inmem", "inmemory":

	default:
		return nil, errors.Errorf("metrics provider %q not supported", cfg.Provider)
	}

	if sink != nil {
		_, err := metrics.NewGlobal(mcfg, sink)
		if err != nil {
			return nil, err
		}
		pmetricskey.StatsVersion.SetGauge(float64(commitNumber))
	}

	xlog.OnError(func(pkg string) {
		pmetricskey.HealthLogErrors.IncrCounter(1, pkg, version)
	})
	pmetricskey.HealthLogErrors.IncrCounter(0, "appinit", version)

	logger.KV(xlog.INFO,
		"status", "metrics_started",
		"provider", cfg.Provider,
		"tags", mcfg.GlobalTags,
	)

	return closer, nil
}

type contextCloser struct {
	ctx context.Context
}

func (c *contextCloser) Close() error {
	if cwSink != nil {
		err := cwSink.Flush()
		if err != nil {
			logger.KV(xlog.ERROR, "reason", "metrics_flush", "err", err.Error())
		}
		logger.ContextKV(c.ctx, xlog.TRACE, "status", "sink_flushed")
	}
	logger.ContextKV(c.ctx, xlog.TRACE, "status", "metrics_closed")

	c.ctx.Done()
	return nil
}