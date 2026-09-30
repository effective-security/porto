// Package telemetry provides http.Handler middleware for request logging and
// request metrics, plus the ResponseCapture writer they rely on to observe
// the status code and body size of a response.
//
//	h := telemetry.NewRequestLogger(next, time.Millisecond, logger,
//		telemetry.WithLoggerSkipPaths([]telemetry.LoggerSkipPath{{Path: "/healthz", Agent: "*"}}))
//	h = telemetry.NewRequestMetrics(h)
//
// Metrics are emitted through porto/metricskey (HTTPReqPerf, HTTPReqByRole)
// keyed by method, status and route template. The restserver Router records
// the template of the route it dispatches to with SetRoute; requests without
// one are labelled UnknownRoute, and non-standard methods OtherMethod, so no
// label value is copied from the request. LoggerSkipPath entries are also
// reused by restserver/authz to suppress access logs; see ShouldSkip.
package telemetry
