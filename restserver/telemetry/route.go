package telemetry

import (
	"context"
	"net/http"
	"sync/atomic"
)

// routeKey is the context key of the *route that NewRequestMetrics attaches
// to each request.
type routeKey struct{}

// route holds the pattern of the route that served a request. The router
// writes it while the handler chain runs, and the metrics handler reads it
// after the chain returns; the pattern is atomic because a handler may keep
// running on another goroutine after that (http.TimeoutHandler).
type route struct {
	pattern atomic.Pointer[string]
}

// withRoute returns r with a route holder in its context and the holder.
// An existing holder is reused, so nested metrics handlers see the same
// route.
func withRoute(r *http.Request) (*http.Request, *route) {
	ctx := r.Context()
	if rt, ok := ctx.Value(routeKey{}).(*route); ok {
		return r, rt
	}
	rt := &route{}
	return r.WithContext(context.WithValue(ctx, routeKey{}, rt)), rt
}

// load returns the recorded pattern, or "" when no route was recorded.
func (rt *route) load() string {
	if p := rt.pattern.Load(); p != nil {
		return *p
	}
	return ""
}

// SetRoute records pattern, the registered route template that matched the
// request (for example "/v1/users/:id"), as the uri label of the metrics
// recorded by NewRequestMetrics. The restserver Router calls it for every
// matched route; custom routers behind NewRequestMetrics call it with ctx
// from the request they dispatch. The pattern must come from the route
// registration, never from the request, so that the label stays bounded.
// The last call wins; without an enclosing NewRequestMetrics it is a no-op.
func SetRoute(ctx context.Context, pattern string) {
	if rt, ok := ctx.Value(routeKey{}).(*route); ok {
		rt.pattern.Store(&pattern)
	}
}
