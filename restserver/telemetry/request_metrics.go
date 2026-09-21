package telemetry

import (
	"net/http"
	"strconv"
	"time"

	"github.com/effective-security/porto/metricskey"
	"github.com/effective-security/porto/xhttp/identity"
)

// requestMetrics is a http.Handler that records execution metrics of the wrapped handler
type requestMetrics struct {
	handler       http.Handler
	responseCodes []string
}

// NewRequestMetrics wraps h so that every request records
// metricskey.HTTPReqPerf (latency) and metricskey.HTTPReqByRole (count)
// labelled by method, status code, URL path and caller role (from
// identity.FromRequest). Responses with status 404 are counted only under a
// fixed "unknown" path to limit cardinality from scanners.
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

func (rm *requestMetrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rc := NewResponseCapture(w)
	rm.handler.ServeHTTP(rc, r)
	role := identity.FromRequest(r).Identity().Role()
	sc := rc.StatusCode()

	// Do not record metrics for 404 errors due to large number of DDoS requests
	if sc != 404 {
		status := rm.statusCode(sc)
		metricskey.HTTPReqPerf.MeasureSince(start, r.Method, status, r.URL.Path)
		metricskey.HTTPReqByRole.IncrCounter(1, r.Method, status, r.URL.Path, role)
	} else {
		metricskey.HTTPReqByRole.IncrCounter(1, r.Method, "404", "unknown", role)
	}
}
