package telemetry

import (
	"cmp"
	"net/http"
	"strconv"
	"time"

	"github.com/effective-security/porto/metricskey"
	"github.com/effective-security/porto/xhttp/identity"
)

const (
	// UnknownRoute is the uri label of requests without a recorded route:
	// unmatched paths and requests answered before or instead of a route
	// handler inside the metrics handler (authz denials, readiness, the
	// restserver CORS preflights, the router's own 405, OPTIONS and
	// redirect responses) or by middleware that does not call SetRoute.
	UnknownRoute = "unknown"
	// OtherMethod is the verb label of requests whose method is not one of
	// the standard net/http methods, as in the OpenTelemetry HTTP semantic
	// conventions.
	OtherMethod = "_OTHER"
)

// requestMetrics is a http.Handler that records execution metrics of the wrapped handler
type requestMetrics struct {
	handler       http.Handler
	responseCodes []string
}

// NewRequestMetrics wraps h so that every request records
// metricskey.HTTPReqPerf (latency) and metricskey.HTTPReqByRole (count)
// labelled by method, status code, route and caller role (from
// identity.FromRequest). No label value is copied from the request, so
// callers cannot create unbounded series: the uri label is the route
// template recorded with SetRoute (the restserver Router records its
// registered path, for example "/v1/users/:id"), or UnknownRoute when no
// route was recorded; the verb label is the request method when it is a
// standard net/http method, or OtherMethod; the role label is whatever the
// identity mapper returned, so it is bounded only if the mapper's roles are.
func NewRequestMetrics(h http.Handler) http.Handler {
	rm := requestMetrics{
		handler:       h,
		responseCodes: make([]string, 599),
	}
	for idx := range rm.responseCodes {
		rm.responseCodes[idx] = strconv.Itoa(idx)
	}
	return &rm
}

func (rm *requestMetrics) statusCode(statusCode int) string {
	if (statusCode < len(rm.responseCodes)) && (statusCode > 0) {
		return rm.responseCodes[statusCode]
	}

	return strconv.Itoa(statusCode)
}

// methodLabel returns method when it is a standard net/http method, and
// OtherMethod otherwise.
func methodLabel(method string) string {
	switch method {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace:
		return method
	}
	return OtherMethod
}

func (rm *requestMetrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	r, rt := withRoute(r)
	rc := NewResponseCapture(w)
	rm.handler.ServeHTTP(rc, r)

	role := identity.FromRequest(r).Identity().Role()
	method := methodLabel(r.Method)
	status := rm.statusCode(rc.StatusCode())
	uri := cmp.Or(rt.load(), UnknownRoute)

	metricskey.HTTPReqPerf.MeasureSince(start, method, status, uri)
	metricskey.HTTPReqByRole.IncrCounter(1, method, status, uri, role)
}
