package telemetry

import (
	"net/http"
	"strings"
	"time"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xlog"
)

// Option is an option that can be passed to New().
type Option option
type option func(c *configuration)

// LoggerSkipPath allows to skip a log for specified Path and Agent
type LoggerSkipPath struct {
	Path  string `json:"path,omitempty" yaml:"path,omitempty"`
	Agent string `json:"agent,omitempty" yaml:"agent,omitempty"`
}

// LoggerSkipPaths allows to skip a log for specified Path and Agent
type LoggerSkipPaths []LoggerSkipPath

// ShouldSkip returns true if the logs should be skipped
func (l LoggerSkipPaths) ShouldSkip(path, userAgent string) bool {
	for _, skip := range l {
		pathMatch := skip.Path == "*" || path == skip.Path
		agentMatch := skip.Agent == "*" || strings.Contains(userAgent, skip.Agent)
		if pathMatch && agentMatch {
			return true
		}
	}
	return false
}

type configuration struct {
	skippaths   LoggerSkipPaths
	granularity int64
	logger      xlog.KeyValueLogger
}

// WithLoggerSkipPaths is an Option allows to skip logs on path/agent match
func WithLoggerSkipPaths(value LoggerSkipPaths) Option {
	return func(c *configuration) {
		c.skippaths = value
	}
}

// RequestLogger is a http.Handler that logs requests and forwards them on down the chain.
type RequestLogger struct {
	handler http.Handler
	cfg     configuration
}

// NewRequestLogger create a new RequestLogger handler, requests are chained to the supplied handler.
// The log includes the clock time to handle the request, with specified granularity (e.g. time.Millisecond).
// skippath parameter allows to specify a list of paths to not log.
func NewRequestLogger(
	handler http.Handler,
	granularity time.Duration,
	logger xlog.KeyValueLogger,
	opts ...Option) http.Handler {

	if handler == nil {
		panic("RequestLogger was supplied a nil handler to delegate to")
	}

	if logger == nil {
		return handler
	}

	cfg := configuration{
		granularity: int64(granularity),
		logger:      logger,
	}

	for _, opt := range opts {
		option(opt)(&cfg)
	}

	return &RequestLogger{
		handler: handler,
		cfg:     cfg,
	}
}

// ServeHTTP implements the http.Handler interface. We wrap the call to the
// real handler to collect info about the response, and then write out the log line
func (l *RequestLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now().UTC()
	rw := NewResponseCapture(w)
	l.handler.ServeHTTP(rw, r)

	agent := r.Header.Get(header.UserAgent)
	if agent == "" {
		agent = "no-agent"
	}

	if l.cfg.skippaths.ShouldSkip(r.URL.Path, agent) {
		return
	}

	dur := time.Since(start)

	l.cfg.logger.ContextKV(r.Context(), xlog.INFO,
		"method", r.Method,
		"path", r.URL.Path,
		"status", rw.statusCode,
		"bytes", rw.bodySize,
		"time", dur.Nanoseconds()/l.cfg.granularity,
		"remote", r.RemoteAddr,
		"agent", agent,
		// use and role added to ctx
		//"role", idn.Role(),
		//"user", idn.Subject(),
	)
}
