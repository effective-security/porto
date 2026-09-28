package limits

import (
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

// Timeouts configures server read deadlines. Zero selects the default for
// that field; a negative duration disables it. These are read deadlines, not
// handler execution or response write deadlines. Streaming callers may need
// to raise or disable Read.
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
}

// WithDefaults returns a copy with zero fields replaced by their defaults.
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
func (t Timeouts) ApplyHTTP(s *http.Server) {
	t = t.WithDefaults()
	s.ReadHeaderTimeout = t.Header
	s.ReadTimeout = t.Read
	s.IdleTimeout = t.Idle
}
