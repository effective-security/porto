package telemetry

import (
	"net/http"
	"strings"
	"time"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
)

// Option configures NewRequestLogger; see WithLoggerSkipPaths.
type Option option
type option func(c *configuration)

// LoggerSkipPath describes requests to exclude from logging by Path and
// User-Agent. Path is compared exactly ("*" matches every path); Agent is a
// substring match ("*" matches every agent). Both must match.
type LoggerSkipPath struct {
	Path  string `json:"path,omitempty" yaml:"path,omitempty"`
	Agent string `json:"agent,omitempty" yaml:"agent,omitempty"`
}

// ShouldSkip reports whether a request for path with the given User-Agent
// matches any entry in cfg and should therefore not be logged.
func ShouldSkip(cfg []LoggerSkipPath, path, userAgent string) bool {
	for _, skip := range cfg {
		pathMatch := skip.Path == "*" || path == skip.Path
		agentMatch := skip.Agent == "*" || strings.Contains(userAgent, skip.Agent)
		if pathMatch && agentMatch {
			return true
		}
	}
	return false
}

type configuration struct {
	skippaths   []LoggerSkipPath
	granularity int64
	logger      xlog.KeyValueLogger
}

// WithLoggerSkipPaths returns an Option that suppresses log lines for
// requests matching any of the given LoggerSkipPath entries.
func WithLoggerSkipPaths(value []LoggerSkipPath) Option {
	return func(c *configuration) {
		c.skippaths = value
	}
}

// RequestLogger is a http.Handler that forwards requests to the wrapped
// handler and then logs one INFO line per request (method, path, status,
// bytes, duration, remote IP, agent) using the request context for
// correlation fields.
type RequestLogger struct {
	handler http.Handler
	cfg     configuration
}

// NewRequestLogger creates a RequestLogger that chains to handler. The
// logged duration is expressed in units of granularity (e.g. time.Millisecond),
// which must be greater than zero. It panics if handler is nil and returns
// handler unchanged (no logging) if logger is nil. The remote address logged
// is identity.ClientIPFromRequest, which honours X-Forwarded-For.
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

	if ShouldSkip(l.cfg.skippaths, r.URL.Path, agent) {
		return
	}

	dur := time.Since(start)

	l.cfg.logger.ContextKV(r.Context(), xlog.INFO,
		"method", r.Method,
		"path", r.URL.Path,
		"status", rw.statusCode,
		"bytes", rw.bodySize,
		"duration", dur.Nanoseconds()/l.cfg.granularity,
		"remote", identity.ClientIPFromRequest(r),
		"agent", agent,
	)
}
