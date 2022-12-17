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
	keyForHTTPReqNotFound   = []string{"http", "request", "status", "not_found"}
	keyForHTTPReqSuccessful = []string{"http", "request", "status", "successful"}
	keyForHTTPReqFailed     = []string{"http", "request", "status", "failed"}
	keyForHTTPReqInvalid    = []string{"http", "request", "status", "invalid"}
	keyForHTTPReqRole       = []string{"http", "request", "role"}
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
		{Name: "status", Value: rm.statusCode(sc)},
		{Name: "uri", Value: r.URL.Path},
	}

	if sc == 404 {
		metrics.IncrCounter(keyForHTTPReqNotFound, 1, tags...)
	} else if sc >= 500 {
		metrics.IncrCounter(keyForHTTPReqFailed, 1, tags...)
	} else if sc >= 400 {
		metrics.IncrCounter(keyForHTTPReqInvalid, 1, tags...)
	} else {
		metrics.MeasureSince(keyForHTTPReqPerf, start, tags...)
		metrics.IncrCounter(keyForHTTPReqSuccessful, 1, tags...)
	}

	metrics.IncrCounter(keyForHTTPReqRole, 1,
		append(tags, metrics.Tag{Name: "role", Value: role})...)
}
