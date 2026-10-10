package gserver

import (
	"cmp"
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth/v7/libstring"
	"github.com/didip/tollbooth/v7/limiter"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// rateLimiter applies RateLimit to one listener. Its HTTP handler limits
// REST requests and its gRPC interceptors limit gRPC and gRPC-Web calls;
// they share the tollbooth buckets, which are keyed on the client address
// and the request path.
type rateLimiter struct {
	lmt *limiter.Limiter
	// trust resolves the client IP of gRPC calls on plaintext listeners,
	// whose context NewTrustedProxyHandler never sees.
	trust *identity.TrustedProxies
	// headerLookups is set when RateLimit.HeadersIPLookups selects the
	// client address from the headers as sent.
	headerLookups bool
	logRejections bool
}

// newRateLimiter returns the limiter described by cfg, which Start has
// already checked with RateLimit.Validate, or nil when cfg is disabled.
func newRateLimiter(cfg *RateLimit, trust *identity.TrustedProxies) *rateLimiter {
	if !cfg.GetEnabled() {
		return nil
	}
	ttl := cfg.ExpirationTTL
	if ttl == 0 {
		ttl = defaultRateLimitTTL
	}
	ops := limiter.ExpirableOptions{
		DefaultExpirationTTL: ttl,
	}

	lmt := tollbooth.NewLimiter(float64(cfg.RequestsPerSecond), &ops)
	if len(cfg.Metods) > 0 {
		lmt.SetMethods(cfg.Metods)
	}
	rl := &rateLimiter{
		lmt:           lmt,
		trust:         trust,
		headerLookups: len(cfg.HeadersIPLookups) > 0,
		logRejections: cfg.GetLogRejections(),
	}
	if rl.headerLookups {
		// Administrator override: tollbooth reads the named headers as sent.
		lmt.SetIPLookups(cfg.HeadersIPLookups)
	} else {
		// Default: tollbooth reads only RemoteAddr, which limitRequest sets
		// to the client IP resolved by the trusted proxy policy.
		lmt.SetIPLookups([]string{rateLookupRemoteAddr})
	}
	logger.KV(xlog.NOTICE,
		"rate_limit", "enabled",
		"log_rejections", rl.logRejections,
	)
	return rl
}

// key returns the address of r's bucket: the client IP resolved by the
// trusted proxy policy (clientIP), or the first address HeadersIPLookups
// finds in r as sent, canonicalized as tollbooth does when it builds the
// bucket key, so an IPv6 address becomes its /64 prefix.
func (rl *rateLimiter) key(r *http.Request) string {
	var ip string
	if rl.headerLookups {
		ip = libstring.RemoteIP(rl.lmt.GetIPLookups(), rl.lmt.GetForwardedForIndexFromBehind(), r)
	} else {
		ip = clientIP(r)
	}
	return libstring.CanonicalizeIP(ip)
}

// clientIP returns the client IP of r resolved by the trusted proxy policy,
// or "" when the socket peer has none, such as a Unix socket peer ("@"):
// its callers would otherwise share one bucket.
func clientIP(r *http.Request) string {
	ip := identity.ClientIPFromRequest(r)
	if _, err := netip.ParseAddr(ip); err != nil {
		return ""
	}
	return ip
}

// limitRequest returns the request tollbooth checks for r: r itself for
// HeadersIPLookups, else a shallow copy whose RemoteAddr is the bare client
// IP. A request without a client IP is not limited.
func (rl *rateLimiter) limitRequest(r *http.Request) *http.Request {
	if rl.headerLookups {
		return r
	}
	limitReq := *r
	limitReq.RemoteAddr = clientIP(r)
	return &limitReq
}

// httpHandler wraps handler with the limiter; a nil limiter returns handler.
// tollbooth echoes the client IP it limits in X-Rate-Limit-Request-Remote-Addr,
// before it folds an IPv6 address to its /64 prefix for the bucket. A
// rejected request never reaches handler: it is answered like
// tollbooth.LimitHandler does, behind the telemetry of an admitted request
// (correlation ID, request metrics with the guest role and UnknownRoute,
// and the request logger with skipPaths), so a 429 is an access-log line.
func (rl *rateLimiter) httpHandler(handler http.Handler, skipPaths []telemetry.LoggerSkipPath) http.Handler {
	if rl == nil {
		return handler
	}
	var reject http.Handler = http.HandlerFunc(rl.rejectHTTP)
	reject = telemetry.NewRequestLogger(reject, requestLogGranularity, logger, telemetry.WithLoggerSkipPaths(skipPaths))
	reject = telemetry.NewRequestMetrics(reject)
	reject = correlation.NewHandler(reject)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if httpErr := tollbooth.LimitByRequest(rl.lmt, w, rl.limitRequest(r)); httpErr != nil {
			reject.ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// rejectHTTP answers a limited request like tollbooth.LimitHandler. It gets
// the original request, and so does tollbooth's OnLimitReached callback,
// which is unused here.
func (rl *rateLimiter) rejectHTTP(w http.ResponseWriter, r *http.Request) {
	if rl.logRejections {
		rl.logRejection(r)
	}
	rl.lmt.ExecOnLimitReached(w, r)
	if rl.lmt.GetOverrideDefaultResponseWriter() {
		return
	}
	w.Header().Add(header.ContentType, rl.lmt.GetMessageContentType())
	w.WriteHeader(rl.lmt.GetStatusCode())
	_, _ = w.Write([]byte(rl.lmt.GetMessage()))
}

// unaryInterceptor limits unary calls; see allowGRPC.
func (rl *rateLimiter) unaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := rl.allowGRPC(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// streamInterceptor limits streaming calls; see allowGRPC.
func (rl *rateLimiter) streamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := rl.allowGRPC(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// allowGRPC returns a ResourceExhausted error, with the tollbooth message,
// when the call to fullMethod in ctx exceeds the limit. tollbooth checks
// the call as the POST to fullMethod it is on the wire (grpcRequest), so
// RateLimit.Metods and the bucket keys apply as to an HTTP request.
func (rl *rateLimiter) allowGRPC(ctx context.Context, fullMethod string) error {
	r := rl.grpcRequest(ctx, fullMethod)
	limitReq := rl.limitRequest(r)
	if tollbooth.ShouldSkipLimiter(rl.lmt, limitReq) {
		return nil
	}
	for _, keys := range tollbooth.BuildKeys(rl.lmt, limitReq) {
		if tollbooth.LimitByKeys(rl.lmt, keys) != nil {
			if rl.logRejections {
				rl.logRejection(r)
			}
			return httperror.NewGrpcFromCtx(ctx, codes.ResourceExhausted, "%s", rl.lmt.GetMessage())
		}
	}
	return nil
}

// grpcRequest returns the HTTP request a gRPC call to fullMethod arrived
// as: a POST from the socket peer, with the forwarding and User-Agent
// metadata as headers, in ctx with the trusted proxy policy.
func (rl *rateLimiter) grpcRequest(ctx context.Context, fullMethod string) *http.Request {
	if rl.trust != nil {
		ctx = identity.WithTrustedProxies(ctx, rl.trust)
	}
	r := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Path: fullMethod,
		},
		Header: http.Header{},
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		r.RemoteAddr = p.Addr.String()
	}
	md, _ := metadata.FromIncomingContext(ctx)
	for _, name := range []string{header.XForwardedFor, header.XRealIP, header.UserAgent} {
		for _, v := range md.Get(name) {
			r.Header.Add(name, v)
		}
	}
	return r.WithContext(ctx)
}

// logRejection records one WARNING line for a rejected request r (or the
// grpcRequest of a rejected call) in its context, so the line carries the
// correlation ID of the access-log or gRPC log line of the same request.
// It shows the limiter key next to the socket peer, the User-Agent and the
// forwarding headers as received.
func (rl *rateLimiter) logRejection(r *http.Request) {
	agent := cmp.Or(r.Header.Get(header.UserAgent), telemetry.NoAgent)
	logger.ContextKV(r.Context(), xlog.WARNING,
		"reason", rateLimitLogReason,
		"method", r.Method,
		"path", r.URL.Path,
		"key", rl.key(r),
		"peer", r.RemoteAddr,
		"agent", agent,
		"xff", strings.Join(r.Header.Values(header.XForwardedFor), ", "),
		"x_real_ip", r.Header.Get(header.XRealIP),
	)
}
