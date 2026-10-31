package limits

import (
	"context"
	"net/http"
	"time"
)

const (
	// DefaultHeaderTimeout bounds the time spent reading HTTP request headers.
	DefaultHeaderTimeout = 10 * time.Second
	// DefaultReadTimeout bounds the time spent reading an entire HTTP request.
	DefaultReadTimeout = 30 * time.Second
	// DefaultIdleTimeout bounds the wait for the next keepalive request.
	DefaultIdleTimeout = 60 * time.Second
	// DefaultHandshakeTimeout bounds TLS handshakes and protocol detection.
	DefaultHandshakeTimeout = 10 * time.Second
	// DefaultMaxRequestBody is the HTTP request body limit in bytes (10 MiB).
	DefaultMaxRequestBody = 10 * 1024 * 1024
)

// Timeouts configures server deadlines. Header, Read, Idle and Handshake are
// read deadlines: zero selects the default for that field and a negative
// duration disables it. Handler is the server-side bound on a request's
// execution; it has no default and is off unless set. There is no response
// write deadline. Streaming callers may need to raise or disable Read and
// leave Handler unset, or set it above their longest stream.
type Timeouts struct {
	// Header sets net/http ReadHeaderTimeout for HTTP/1.x headers.
	// HTTP/2 has no per-stream header deadline in net/http.
	Header time.Duration `json:"header,omitempty" yaml:"header,omitempty"`
	// Read limits reading the whole HTTP request, including its body.
	Read time.Duration `json:"read,omitempty" yaml:"read,omitempty"`
	// Idle limits waiting for the next HTTP keepalive request.
	Idle time.Duration `json:"idle,omitempty" yaml:"idle,omitempty"`
	// Handshake limits cmux detection and transport's eager TLS handshake.
	// net/http TLS listeners use the smaller positive Header or Read deadline.
	Handshake time.Duration `json:"handshake,omitempty" yaml:"handshake,omitempty"`
	// Handler bounds the execution of each request: its context expires
	// Handler after the server starts handling it, unless the client asked
	// for an earlier deadline, which is kept. Zero and negative leave
	// requests bounded only by the client's deadline (the default). It
	// applies to REST requests and to gRPC and gRPC-Web calls, streams
	// included; a handler that ignores its context outlives the deadline.
	// It is not a net/http setting, so ApplyHTTP does not apply it: servers
	// wrap their handler chain with ApplyHandler and gRPC interceptors use
	// HandlerContext.
	Handler time.Duration `json:"handler,omitempty" yaml:"handler,omitempty"`
}

// WithDefaults returns a copy with zero read deadlines replaced by their
// defaults. Handler has no default and is returned as is.
func (t Timeouts) WithDefaults() Timeouts {
	if t.Header == 0 {
		t.Header = DefaultHeaderTimeout
	}
	if t.Read == 0 {
		t.Read = DefaultReadTimeout
	}
	if t.Idle == 0 {
		t.Idle = DefaultIdleTimeout
	}
	if t.Handshake == 0 {
		t.Handshake = DefaultHandshakeTimeout
	}
	return t
}

// ApplyHTTP sets the read deadlines on a server before it starts serving.
// Negative values are preserved to disable net/http's fallback deadlines.
// Handler is not a server setting; see ApplyHandler.
func (t Timeouts) ApplyHTTP(s *http.Server) {
	t = t.WithDefaults()
	s.ReadHeaderTimeout = t.Header
	s.ReadTimeout = t.Read
	s.IdleTimeout = t.Idle
}

// HandlerContext returns ctx bounded by t.Handler: when Handler is positive,
// the returned context expires after Handler unless ctx already has an
// earlier deadline, which is kept. Otherwise ctx is returned unchanged with a
// cancel function that does nothing. The caller must call cancel when the
// request ends to release the timer.
func (t Timeouts) HandlerContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if t.Handler <= 0 {
		return ctx, func() {}
	}
	// context.WithTimeout keeps an earlier parent deadline.
	return context.WithTimeout(ctx, t.Handler)
}

// ApplyHandler returns handler served with each request's context bounded by
// t.Handler (see HandlerContext). When Handler is not positive it returns
// handler itself. Servers call it on their handler chain before serving.
func (t Timeouts) ApplyHandler(handler http.Handler) http.Handler {
	if t.Handler <= 0 {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := t.HandlerContext(r.Context())
		defer cancel()
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
