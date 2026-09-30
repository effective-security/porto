package metricskey

import "github.com/effective-security/metrics"

// Descriptors of the metrics emitted by this repo.
var (
	// HTTPReqPerf samples HTTP request latency by verb, status and URI
	// (restserver/telemetry). The uri tag is the matched route template or
	// "unknown", and verb is "_OTHER" for non-standard methods.
	HTTPReqPerf = metrics.Describe{
		Name:         "http_requests_perf",
		Type:         metrics.TypeSample,
		RequiredTags: []string{"verb", "status", "uri"},
		Help:         "provides quantiles for HTTP request.",
	}
	// HTTPReqByRole counts HTTP requests by verb, status, URI and caller
	// role, with the same verb and uri tags as HTTPReqPerf.
	HTTPReqByRole = metrics.Describe{
		Name:         "http_requests_role",
		Type:         metrics.TypeCounter,
		RequiredTags: []string{"verb", "status", "uri", "role"},
		Help:         "provides counts for HTTP request by role.",
	}

	// GRPCReqPerf samples gRPC request latency by API and status code (gserver).
	GRPCReqPerf = metrics.Describe{
		Name:         "rpc_requests_perf",
		Type:         metrics.TypeSample,
		RequiredTags: []string{"api", "status"},
		Help:         "provides quantiles for gRPC request.",
	}
	// GRPCReqByRole counts gRPC requests by API, status code and caller role.
	GRPCReqByRole = metrics.Describe{
		Name:         "rpc_requests_role",
		Type:         metrics.TypeCounter,
		RequiredTags: []string{"api", "status", "role"},
		Help:         "provides counts for gRPC request by role.",
	}

	// StatsVersion is a gauge set to the commit number by appinit.Metrics.
	StatsVersion = metrics.Describe{
		Type: metrics.TypeGauge,
		Name: "version",
		Help: "version provides the deployed version",
		//RequiredTags: []string{},
	}
	// HealthLogErrors counts errors written to the log, by package and build
	// (incremented from the xlog error hook installed by appinit.Metrics).
	HealthLogErrors = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "log_errors",
		Help:         "log_errors provides the counter of errors in logs",
		RequiredTags: []string{"pkg", "build"},
	}
)

// Metrics lists every descriptor in this package, for registering help text
// with a sink (see appinit.Metrics).
var Metrics = []*metrics.Describe{
	&HTTPReqPerf,
	&HTTPReqByRole,
	&GRPCReqPerf,
	&GRPCReqByRole,
	&StatsVersion,
	&HealthLogErrors,
}
