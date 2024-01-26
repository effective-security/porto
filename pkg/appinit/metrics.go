package appinit

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
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
	if cfg.Provider == "" || cfg.GetDisabled() {
		logger.KV(xlog.INFO,
			"status", "metrics_disabled",
			"version", version,
			"commit", commitNumber,
			"provider", cfg.Provider,
		)
		return nil, nil
	}

	var err error
	var sinks []metrics.Sink
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
		case "pod":
			if podn := os.Getenv("POD_NAME"); podn != "" {
				l := len(podn)
				if l > 5 {
					// kubes uses random suffixes
					podn = podn[l-5 : l]
				}
				mcfg.GlobalTags = append(mcfg.GlobalTags, metrics.Tag{Name: tag, Value: podn})
			}
		}
	}

	providers := strings.Split(cfg.Provider, ",")

	for _, p := range providers {
		switch p {
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
						logger.KV(xlog.INFO,
							"status", "starting_prometheus",
							"endpoint", cfg.Prometheus.Addr)
						// remove Prom metrics
						h := promhttp.HandlerFor(prom.DefaultGatherer, promhttp.HandlerOpts{})
						logger.Fatal(http.ListenAndServe(cfg.Prometheus.Addr, h).Error())
					}()
				}
			}
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

			cwSink, err = cloudwatch.NewSink(&c)
			if err != nil {
				return nil, err
			}

			ctxcloser := &contextCloser{
				ctx: context.Background(),
			}

			go cwSink.Run(ctxcloser.ctx)
			sinks = append(sinks, promSink)
			closer = ctxcloser

		case "inmem", "inmemory":

		case "":

		default:
			return nil, errors.Errorf("metrics provider %q not supported", cfg.Provider)
		}
	}
	var sink metrics.Sink

	if len(sinks) == 1 {
		sink = sinks[0]
	} else if len(sinks) > 1 {
		sink = metrics.NewFanoutSink(sinks...)
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

	logger.KV(xlog.INFO,
		"status", "metrics_started",
		"version", version,
		"commit", commitNumber,
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
