package gserver

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	// rateLimitRemoteAddrHeader is the tollbooth response header that
	// echoes the address the limiter keyed on.
	rateLimitRemoteAddrHeader = "X-Rate-Limit-Request-Remote-Addr"
	// unixPeer is the RemoteAddr of a caller on a Unix socket.
	unixPeer = "@"
)

func TestDefaultRateLimitUsesTrustedClient(t *testing.T) {
	t.Parallel()
	enabled := true
	trust, err := identity.ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	for _, tt := range []struct {
		name       string
		trust      *identity.TrustedProxies
		remote     string
		firstXFF   string
		secondXFF  string
		firstKey   string
		secondKey  string
		secondCode int
	}{
		{"direct header spoof", nil, "198.51.100.7:123", "203.0.113.1", "203.0.113.2", "198.51.100.7", "198.51.100.7", http.StatusTooManyRequests},
		{"trusted same client", trust, "10.0.0.2:123", "203.0.113.1", "203.0.113.1", "203.0.113.1", "203.0.113.1", http.StatusTooManyRequests},
		{"trusted distinct clients", trust, "10.0.0.2:123", "203.0.113.1", "203.0.113.2", "203.0.113.1", "203.0.113.2", http.StatusOK},
		{"mapped IPv4 clients", trust, "10.0.0.2:123", "::ffff:203.0.113.1", "::ffff:203.0.113.2", "203.0.113.1", "203.0.113.2", http.StatusOK},
		{"IPv6 peer", nil, "[2001:db8::7]:123", "", "", "2001:db8::7", "2001:db8::7", http.StatusTooManyRequests},
		// tollbooth does not limit a request without a client IP.
		{"no peer", trust, "", "203.0.113.1", "203.0.113.1", "", "", http.StatusOK},
		// a Unix socket peer has no client IP, even with trusted forwarding
		{"unix peer", trust, unixPeer, "203.0.113.1", "203.0.113.1", "", "", http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var seen []*http.Request
			h := newRateLimiter(&RateLimit{Enabled: &enabled, RequestsPerSecond: 1}, nil).httpHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = append(seen, r)
				w.WriteHeader(http.StatusOK)
			}), nil)
			h = identity.NewTrustedProxyHandler(h, tt.trust)
			for i, xff := range []string{tt.firstXFF, tt.secondXFF} {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = tt.remote
				if xff != "" {
					r.Header.Set(header.XForwardedFor, xff)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				wantCode, wantKey := http.StatusOK, tt.firstKey
				if i == 1 {
					wantCode, wantKey = tt.secondCode, tt.secondKey
				}
				assert.Equal(t, wantCode, w.Code)
				assert.Equal(t, wantKey, w.Header().Get(rateLimitRemoteAddrHeader))
				if wantCode == http.StatusOK {
					require.Len(t, seen, i+1)
					assert.Equal(t, tt.remote, seen[i].RemoteAddr, "handler must see the socket peer")
				}
			}
		})
	}
}

// TestDefaultRateLimitRejection checks that the default limiter answers a
// rejected request the same way tollbooth.LimitHandler does.
func TestDefaultRateLimitRejection(t *testing.T) {
	t.Parallel()
	enabled := true
	calls := 0
	h := newRateLimiter(&RateLimit{Enabled: &enabled, RequestsPerSecond: 1}, nil).httpHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}), nil)
	h = identity.NewTrustedProxyHandler(h, nil)

	codes := make([]int, 0, 2)
	var rejected *httptest.ResponseRecorder
	for range 2 {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "198.51.100.7:123"
		rejected = httptest.NewRecorder()
		h.ServeHTTP(rejected, r)
		codes = append(codes, rejected.Code)
	}
	assert.Equal(t, []int{http.StatusOK, http.StatusTooManyRequests}, codes)
	assert.Equal(t, 1, calls)
	assert.Equal(t, "text/plain; charset=utf-8", rejected.Header().Get(header.ContentType))
	assert.Equal(t, "You have reached maximum request limit.", rejected.Body.String())
}

// TestRateLimitMethods checks that a limiter with Metods limits only the
// listed methods.
func TestRateLimitMethods(t *testing.T) {
	t.Parallel()
	enabled := true
	h := newRateLimiter(&RateLimit{
		Enabled:           &enabled,
		RequestsPerSecond: 1,
		Metods:            []string{http.MethodPost},
	}, nil).httpHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)
	h = identity.NewTrustedProxyHandler(h, nil)

	var got []int
	for _, method := range []string{http.MethodGet, http.MethodGet, http.MethodGet, http.MethodPost, http.MethodPost} {
		r := httptest.NewRequest(method, "/", nil)
		r.RemoteAddr = "198.51.100.7:123"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		got = append(got, w.Code)
	}
	assert.Equal(t, []int{
		http.StatusOK,
		http.StatusOK,
		http.StatusOK,
		http.StatusOK,
		http.StatusTooManyRequests,
	}, got)
}

func TestRateLimitGetLogRejections(t *testing.T) {
	t.Parallel()
	var cfg *RateLimit
	assert.False(t, cfg.GetLogRejections())
	cfg = &RateLimit{}
	assert.False(t, cfg.GetLogRejections())
	on := true
	cfg.LogRejections = &on
	assert.True(t, cfg.GetLogRejections())
}

// TestNewRateLimiterDisabled checks that a disabled limiter is nil and
// leaves the HTTP handler unwrapped.
func TestNewRateLimiterDisabled(t *testing.T) {
	t.Parallel()
	disabled := false
	assert.Nil(t, newRateLimiter(nil, nil))
	assert.Nil(t, newRateLimiter(&RateLimit{Enabled: &disabled, RequestsPerSecond: 1}, nil))

	var rl *rateLimiter
	h := http.NewServeMux()
	assert.Same(t, h, rl.httpHandler(h, nil))
}

func TestRateLimitKey(t *testing.T) {
	t.Parallel()
	enabled := true
	for _, tt := range []struct {
		name    string
		lookups []string
		remote  string
		xff     string
		realIP  string
		want    string
	}{
		{
			name:   "default ignores untrusted forwarding",
			remote: "10.0.0.5:443",
			xff:    "203.0.113.1",
			want:   "10.0.0.5",
		},
		{
			name:   "default has no key for a Unix peer",
			remote: unixPeer,
			want:   "",
		},
		{
			name:    "socket with port",
			lookups: []string{rateLookupRemoteAddr},
			remote:  "10.0.0.5:443",
			want:    "10.0.0.5",
		},
		{
			name:    "socket without port",
			lookups: []string{rateLookupRemoteAddr},
			remote:  "10.0.0.5",
			want:    "10.0.0.5",
		},
		{
			name:    "IPv6 socket is its /64 prefix",
			lookups: []string{rateLookupRemoteAddr},
			remote:  "[2001:db8::7]:123",
			want:    "2001:db8::",
		},
		{
			name:   "default IPv6 is its /64 prefix",
			remote: "[2001:db8:0:1:aa::7]:443",
			want:   "2001:db8:0:1::",
		},
		{
			name:   "default IPv6 in the same /64 shares the key",
			remote: "[2001:db8:0:1:bb::9]:443",
			want:   "2001:db8:0:1::",
		},
		{
			name:    "forwarded IPv6 is its /64 prefix",
			lookups: []string{header.XForwardedFor},
			remote:  "10.0.0.5:443",
			xff:     "2001:db8:0:2::42",
			want:    "2001:db8:0:2::",
		},
		{
			name:    "last forwarded address",
			lookups: []string{header.XForwardedFor, rateLookupRemoteAddr},
			remote:  "10.0.0.5:443",
			xff:     "198.51.100.1, 203.0.113.50",
			want:    "203.0.113.50",
		},
		{
			name:    "empty forwarded list falls through",
			lookups: []string{header.XForwardedFor, rateLookupXRealIP},
			remote:  "10.0.0.5:443",
			realIP:  "198.51.100.20",
			want:    "198.51.100.20",
		},
		{
			name:    "no match",
			lookups: []string{header.XForwardedFor, rateLookupXRealIP},
			remote:  "10.0.0.5:443",
			want:    "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rl := newRateLimiter(&RateLimit{
				Enabled:           &enabled,
				RequestsPerSecond: 1,
				HeadersIPLookups:  tt.lookups,
			}, nil)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			if tt.xff != "" {
				r.Header.Set(header.XForwardedFor, tt.xff)
			}
			if tt.realIP != "" {
				r.Header.Set(header.XRealIP, tt.realIP)
			}
			assert.Equal(t, tt.want, rl.key(r))
		})
	}
}

// grpcCallContext returns the server context of a gRPC call from
// peerAddr (an IP and port, unixPeer, or "" for none) with the incoming
// metadata md.
func grpcCallContext(t *testing.T, peerAddr string, md metadata.MD) context.Context {
	t.Helper()
	ctx := context.Background()
	switch peerAddr {
	case "":
	case unixPeer:
		ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.UnixAddr{Name: unixPeer, Net: "unix"}})
	default:
		addr, err := netip.ParseAddrPort(peerAddr)
		require.NoError(t, err)
		ctx = peer.NewContext(ctx, &peer.Peer{Addr: net.TCPAddrFromAddrPort(addr)})
	}
	return metadata.NewIncomingContext(ctx, md)
}

// TestRateLimitGRPC checks that gRPC calls are limited per client address
// and method path, keyed like HTTP requests: on the peer unless it is a
// trusted proxy, or on the HeadersIPLookups metadata as sent.
func TestRateLimitGRPC(t *testing.T) {
	t.Parallel()
	enabled := true
	trust, err := identity.ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	const (
		method      = "/pkg.Service/Method"
		otherMethod = "/pkg.Service/Other"
	)
	xff := func(v string) metadata.MD { return metadata.Pairs(header.XForwardedFor, v) }
	realIP := func(v string) metadata.MD { return metadata.Pairs(header.XRealIP, v) }
	for _, tt := range []struct {
		name    string
		cfg     RateLimit
		trust   *identity.TrustedProxies
		peer    string
		first   metadata.MD
		second  metadata.MD
		limited bool
	}{
		{
			name:    "untrusted peer shares one bucket",
			peer:    "10.0.0.5:443",
			first:   xff("203.0.113.1"),
			second:  xff("203.0.113.2"),
			limited: true,
		},
		{
			name:   "trusted proxy distinct clients",
			trust:  trust,
			peer:   "10.0.0.2:123",
			first:  xff("203.0.113.1"),
			second: xff("203.0.113.2"),
		},
		{
			name:    "trusted proxy same client",
			trust:   trust,
			peer:    "10.0.0.2:123",
			first:   xff("203.0.113.1"),
			second:  xff("203.0.113.1"),
			limited: true,
		},
		{
			name:   "header lookups distinct clients",
			cfg:    RateLimit{HeadersIPLookups: []string{rateLookupXRealIP}},
			peer:   "10.0.0.2:123",
			first:  realIP("198.51.100.1"),
			second: realIP("198.51.100.2"),
		},
		{
			name:    "header lookups same client",
			cfg:     RateLimit{HeadersIPLookups: []string{rateLookupXRealIP}},
			peer:    "10.0.0.2:123",
			first:   realIP("198.51.100.1"),
			second:  realIP("198.51.100.1"),
			limited: true,
		},
		{
			// gRPC calls are POSTs
			name: "methods without POST",
			cfg:  RateLimit{Metods: []string{http.MethodGet}},
			peer: "10.0.0.5:443",
		},
		{
			name: "methods with POST",
			cfg:  RateLimit{Metods: []string{http.MethodPost}},
			peer: "10.0.0.5:443",
			// a nil MD is a call without metadata
			limited: true,
		},
		{
			// tollbooth does not limit a request without a client IP
			name: "no peer",
		},
		{
			// a Unix socket peer has no client IP, even with trusted forwarding
			name:   "unix peer",
			trust:  trust,
			peer:   unixPeer,
			first:  xff("203.0.113.1"),
			second: xff("203.0.113.1"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := tt.cfg
			cfg.Enabled = &enabled
			cfg.RequestsPerSecond = 1
			rl := newRateLimiter(&cfg, tt.trust)

			require.NoError(t, rl.allowGRPC(grpcCallContext(t, tt.peer, tt.first), method))
			err := rl.allowGRPC(grpcCallContext(t, tt.peer, tt.second), method)
			if tt.limited {
				assert.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)
				assert.Equal(t, "You have reached maximum request limit.", status.Convert(err).Message())
			} else {
				assert.NoError(t, err)
			}
			// each method path has its own bucket
			assert.NoError(t, rl.allowGRPC(grpcCallContext(t, tt.peer, tt.second), otherMethod))
		})
	}
}

// ctxServerStream is a grpc.ServerStream that only has a context.
type ctxServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *ctxServerStream) Context() context.Context { return s.ctx }

// TestRateLimitGRPCInterceptors checks that the interceptors call the
// handler for an admitted call only, and that a rejection carries the
// call's correlation ID.
func TestRateLimitGRPCInterceptors(t *testing.T) {
	t.Parallel()
	enabled := true
	rl := newRateLimiter(&RateLimit{Enabled: &enabled, RequestsPerSecond: 1}, nil)
	ctx := correlation.WithID(grpcCallContext(t, "198.51.100.7:123", nil))

	unary := rl.unaryInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Service/Unary"}
	calls := 0
	handler := func(_ context.Context, req any) (any, error) {
		calls++
		return req, nil
	}
	res, err := unary(ctx, "req", info, handler)
	require.NoError(t, err)
	assert.Equal(t, "req", res)
	res, err = unary(ctx, "req", info, handler)
	assert.Nil(t, res)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)
	var herr *httperror.Error
	require.ErrorAs(t, err, &herr)
	assert.Equal(t, correlation.ID(ctx), herr.RequestID)
	assert.Equal(t, 1, calls)

	stream := rl.streamInterceptor()
	sinfo := &grpc.StreamServerInfo{FullMethod: "/pkg.Service/Stream"}
	ss := &ctxServerStream{ctx: ctx}
	streams := 0
	sh := func(any, grpc.ServerStream) error {
		streams++
		return nil
	}
	require.NoError(t, stream(nil, ss, sinfo, sh))
	err = stream(nil, ss, sinfo, sh)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)
	assert.Equal(t, 1, streams)
}

// TestRateLimitRejectionLog checks that a 429 is an access-log line with
// the correlation ID it was answered with, that LogRejections adds a
// WARNING line with the limiter key and the same correlation ID for HTTP
// and gRPC, and that a skipped path suppresses only the access line.
func TestRateLimitRejectionLog(t *testing.T) {
	// not parallel: installs a process-global log formatter
	var logs bytes.Buffer
	remove := xlog.InstallFormatter(xlog.NewStringFormatter(&logs))
	t.Cleanup(remove)

	enabled := true
	logOn := true
	trust, err := identity.ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	limiter := func(cfg *RateLimit, trust *identity.TrustedProxies, skip ...telemetry.LoggerSkipPath) http.Handler {
		h := newRateLimiter(cfg, trust).httpHandler(ok, skip)
		logs.Reset()
		return identity.NewTrustedProxyHandler(h, trust)
	}
	serve := func(h http.Handler, remote, xff, realIP, agent string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/v1/items", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set(header.XForwardedFor, xff)
		}
		if realIP != "" {
			r.Header.Set(header.XRealIP, realIP)
		}
		if agent != "" {
			r.Header.Set(header.UserAgent, agent)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	admit := func(h http.Handler, remote, xff, realIP, agent string) {
		t.Helper()
		require.Equal(t, http.StatusOK, serve(h, remote, xff, realIP, agent).Code)
		assert.NotContains(t, logs.String(), "status=429")
		assert.NotContains(t, logs.String(), "reason="+rateLimitLogReason)
	}
	// reject returns the correlation ID of the 429 it expects.
	reject := func(h http.Handler, remote, xff, realIP, agent string) string {
		t.Helper()
		w := serve(h, remote, xff, realIP, agent)
		require.Equal(t, http.StatusTooManyRequests, w.Code)
		cid := w.Header().Get(header.XCorrelationID)
		require.NotEmpty(t, cid)
		return cid
	}
	// accessLine checks the request logger's line of a 429 sent to agent.
	accessLine := func(cid, remote, agent string) {
		t.Helper()
		assert.Equal(t, 1, strings.Count(logs.String(), "status=429"))
		assert.Contains(t, logs.String(), `ctx=`+cid+` method=GET path="/v1/items" status=429 bytes=39 duration=`)
		assert.Contains(t, logs.String(), `remote=`+remote+` agent=`+agent+"\n")
	}

	// An untrusted peer ignores X-Forwarded-For, so every caller behind
	// that socket shares one bucket keyed on the internal address.
	shared := limiter(&RateLimit{
		Enabled:           &enabled,
		RequestsPerSecond: 1,
		LogRejections:     &logOn,
	}, nil)
	admit(shared, "10.0.0.5:443", "203.0.113.1", "", "caller-a")
	cid := reject(shared, "10.0.0.5:443", "203.0.113.2", "", "caller-b")
	accessLine(cid, "10.0.0.5", "caller-b")
	assert.Contains(t, logs.String(),
		`ctx=`+cid+` reason=rate_limit method=GET path="/v1/items" key=10.0.0.5 peer="10.0.0.5:443" agent=caller-b xff=203.0.113.2`+"\n")

	trusted := limiter(&RateLimit{
		Enabled:           &enabled,
		RequestsPerSecond: 1,
		LogRejections:     &logOn,
	}, trust)
	admit(trusted, "10.0.0.2:123", "203.0.113.8", "", "caller-c")
	admit(trusted, "10.0.0.2:123", "203.0.113.9", "", "caller-d")
	cid = reject(trusted, "10.0.0.2:123", "203.0.113.8", "", "")
	accessLine(cid, "203.0.113.8", "no-agent")
	assert.Contains(t, logs.String(),
		`ctx=`+cid+` reason=rate_limit method=GET path="/v1/items" key=203.0.113.8 peer="10.0.0.2:123" agent=no-agent xff=203.0.113.8`+"\n")

	// Off by default: the 429 is still an access-log line.
	silent := limiter(&RateLimit{
		Enabled:           &enabled,
		RequestsPerSecond: 1,
	}, nil)
	admit(silent, "10.0.0.6:443", "", "", "caller-e")
	cid = reject(silent, "10.0.0.6:443", "", "", "caller-e")
	accessLine(cid, "10.0.0.6", "caller-e")
	assert.NotContains(t, logs.String(), "reason="+rateLimitLogReason)

	// Header lookups key on the header, not on the trusted client IP that
	// the access line shows as remote.
	lookedUp := limiter(&RateLimit{
		Enabled:           &enabled,
		RequestsPerSecond: 1,
		LogRejections:     &logOn,
		HeadersIPLookups:  []string{rateLookupXRealIP},
	}, trust)
	admit(lookedUp, "10.0.0.2:123", "203.0.113.8", "198.51.100.20", "caller-f")
	admit(lookedUp, "10.0.0.2:123", "203.0.113.8", "198.51.100.21", "caller-g")
	cid = reject(lookedUp, "10.0.0.2:123", "203.0.113.8", "198.51.100.20", "caller-f")
	accessLine(cid, "203.0.113.8", "caller-f")
	assert.Contains(t, logs.String(),
		`ctx=`+cid+` reason=rate_limit method=GET path="/v1/items" key=198.51.100.20 peer="10.0.0.2:123" agent=caller-f xff=203.0.113.8 x_real_ip=198.51.100.20`+"\n")

	// IPv6 callers in one /64 share a bucket: the key is that prefix, while
	// the access line shows the caller's address.
	ipv6 := limiter(&RateLimit{
		Enabled:           &enabled,
		RequestsPerSecond: 1,
		LogRejections:     &logOn,
	}, nil)
	admit(ipv6, "[2001:db8:0:1:aa::7]:443", "", "", "caller-i")
	cid = reject(ipv6, "[2001:db8:0:1:bb::9]:443", "", "", "caller-j")
	accessLine(cid, `"2001:db8:0:1:bb::9"`, "caller-j")
	assert.Contains(t, logs.String(),
		`ctx=`+cid+` reason=rate_limit method=GET path="/v1/items" key="2001:db8:0:1::" peer="[2001:db8:0:1:bb::9]:443" agent=caller-j`+"\n")

	// A skipped path has no access line, but LogRejections still logs.
	skipped := limiter(&RateLimit{
		Enabled:           &enabled,
		RequestsPerSecond: 1,
		LogRejections:     &logOn,
	}, nil, telemetry.LoggerSkipPath{Path: "/v1/items", Agent: "*"})
	admit(skipped, "10.0.0.7:443", "", "", "caller-h")
	cid = reject(skipped, "10.0.0.7:443", "", "", "caller-h")
	assert.NotContains(t, logs.String(), "status=429")
	assert.Contains(t, logs.String(),
		`ctx=`+cid+` reason=rate_limit method=GET path="/v1/items" key=10.0.0.7 peer="10.0.0.7:443" agent=caller-h`+"\n")

	// gRPC: the line carries the call's correlation ID, method path and
	// metadata.
	rl := newRateLimiter(&RateLimit{
		Enabled:           &enabled,
		RequestsPerSecond: 1,
		LogRejections:     &logOn,
	}, trust)
	logs.Reset()
	md := metadata.Pairs(
		header.XForwardedFor, "203.0.113.8",
		header.XForwardedFor, "10.0.0.3",
		header.UserAgent, "grpc-test",
	)
	ctx := correlation.WithID(grpcCallContext(t, "10.0.0.2:123", md))
	require.NoError(t, rl.allowGRPC(ctx, "/pkg.Service/Method"))
	assert.NotContains(t, logs.String(), "reason="+rateLimitLogReason)
	err = rl.allowGRPC(ctx, "/pkg.Service/Method")
	require.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)
	assert.Contains(t, logs.String(),
		`ctx=`+correlation.ID(ctx)+` reason=rate_limit method=POST path="/pkg.Service/Method" key=203.0.113.8 peer="10.0.0.2:123" agent=grpc-test xff="203.0.113.8, 10.0.0.3"`+"\n")
}
