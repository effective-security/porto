// Package telemetry provides http.Handler middleware for request logging and
// request metrics, plus the ResponseCapture writer they rely on to observe
// the status code and body size of a response.
//
//	h := telemetry.NewRequestLogger(next, time.Millisecond, logger,
//		telemetry.WithLoggerSkipPaths([]telemetry.LoggerSkipPath{{Path: "/healthz", Agent: "*"}}))
//	h = telemetry.NewRequestMetrics(h)
//
// Metrics are emitted through porto/metricskey (HTTPReqPerf, HTTPReqByRole)
// keyed by method, status and URL path. LoggerSkipPath entries are also
// reused by restserver/authz to suppress access logs; see ShouldSkip.
package telemetry
