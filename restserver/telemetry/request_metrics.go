package telemetry

import (
	"net/http"
	"strconv"
	"time"

	"github.com/effective-security/metrics"
	"github.com/effective-security/porto/xhttp/identity"
)

var (
	keyForHTTPReqPerf       = []string{"http", "request", "perf"}
	keyForHTTPReqSuccessful = []string{"http", "request", "status", "successful"}
	keyForHTTPReqFailed     = []string{"http", "request", "status", "failed"}
)

// a http.Handler that records execution metrics of the wrapper handler
type requestMetrics struct {
	handler       http.Handler
	responseCodes []string
}

// NewRequestMetrics creates a wrapper handler to produce metrics for each request
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

	tags := []metrics.Tag{
		{Name: "method", Value: r.Method},
		{Name: "role", Value: role},
		{Name: "status", Value: rm.statusCode(sc)},
		{Name: "uri", Value: r.URL.Path},
	}

	metrics.MeasureSince(keyForHTTPReqPerf, start, tags...)

	if sc >= 400 {
		metrics.IncrCounter(keyForHTTPReqFailed, 1, tags...)
	} else {
		metrics.IncrCounter(keyForHTTPReqSuccessful, 1, tags...)
	}
}
