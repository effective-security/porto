package telemetry

import (
	"context"
	"net/http"
	"sync/atomic"

	"github.com/effective-security/porto/xhttp/identity"
)

// labelsKey is the context key of the *requestLabels that NewRequestMetrics
// attaches to each request.
type labelsKey struct{}

// requestLabels holds the label values that handlers inside the metrics
// handler report for a request: the pattern of the route that served it
// and the caller role seen by a nested NewRequestMetrics. They are written
// while the handler chain runs and read by the metrics handler after the
// chain returns; they are atomic because a handler may keep running on
// another goroutine after that (http.TimeoutHandler).
type requestLabels struct {
	route atomic.Pointer[string]
	role  atomic.Pointer[string]
}

// withLabels returns r with a label holder in its context, the holder and
// whether it was created here. An existing holder is reused, so nested
// metrics handlers share it and only the outermost one records.
func withLabels(r *http.Request) (*http.Request, *requestLabels, bool) {
	ctx := r.Context()
	if l, ok := ctx.Value(labelsKey{}).(*requestLabels); ok {
		return r, l, false
	}
	l := &requestLabels{}
	return r.WithContext(context.WithValue(ctx, labelsKey{}, l)), l, true
}

// routePattern returns the recorded route pattern, or "" when no route was
// recorded.
func (l *requestLabels) routePattern() string {
	if p := l.route.Load(); p != nil {
		return *p
	}
	return ""
}

// callerRole returns the role reported by a nested metrics handler, or the
// role of the identity in ctx when none was reported.
func (l *requestLabels) callerRole(ctx context.Context) string {
	if role := l.role.Load(); role != nil {
		return *role
	}
	return identity.FromContext(ctx).Identity().Role()
}

// SetRoute records pattern, the registered route template that matched the
// request (for example "/v1/users/:id"), as the uri label of the metrics
// recorded by NewRequestMetrics. The restserver Router calls it for every
// matched route; custom routers behind NewRequestMetrics call it with ctx
// from the request they dispatch. The pattern must come from the route
// registration, never from the request, so that the label stays bounded.
// The last call wins; without an enclosing NewRequestMetrics it is a no-op.
func SetRoute(ctx context.Context, pattern string) {
	if l, ok := ctx.Value(labelsKey{}).(*requestLabels); ok {
		l.route.Store(&pattern)
	}
}
