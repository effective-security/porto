package appinit

import (
	"net"
	"net/http"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/appinit/config"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/xlog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type prometheusServer struct {
	server   *http.Server
	listener net.Listener
	done     chan struct{}
	once     sync.Once
	err      error
}

func newPrometheusServer(cfg *config.Prometheus) (*prometheusServer, error) {
	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to listen for Prometheus on %s", cfg.Addr)
	}
	server := &http.Server{
		Handler: prometheusHandler(cfg, prometheus.DefaultRegisterer, prometheus.DefaultGatherer),
	}
	cfg.Timeouts.ApplyHTTP(server)
	return &prometheusServer{
		server:   server,
		listener: listener,
	}, nil
}

// prometheusHandler serves the metrics of gatherer as promhttp.Handler does
// (instrumented in registerer), with the request body bounded by
// cfg.MaxRequestBody. With cfg.Timeouts.Handler set, a scrape that takes
// longer is answered 503 through promhttp.HandlerOpts.Timeout
// (http.TimeoutHandler, which also bounds the request context): promhttp
// gathers without consulting the request context, so a context deadline
// alone would not end a slow scrape. The collection itself still finishes
// in the background.
func prometheusHandler(cfg *config.Prometheus, registerer prometheus.Registerer, gatherer prometheus.Gatherer) http.Handler {
	handler := promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{Timeout: cfg.Timeouts.Handler})
	handler = promhttp.InstrumentMetricHandler(registerer, handler)
	return marshal.LimitRequestBody(handler, cfg.MaxRequestBody)
}

func (p *prometheusServer) start() {
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		if err := p.server.Serve(p.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.KV(xlog.ERROR, "reason", "prometheus_serve", "err", err)
		}
	}()
}

func (p *prometheusServer) Close() error {
	p.once.Do(func() {
		p.err = errors.WithMessage(p.server.Close(), "unable to close Prometheus server")
		// Also owns the listener before Serve starts, including failed initialization.
		if err := p.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			p.err = errors.CombineErrors(p.err, errors.WithMessage(err, "unable to close Prometheus listener"))
		}
		if p.done != nil {
			<-p.done
		}
	})
	return p.err
}
