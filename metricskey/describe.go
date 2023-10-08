package metricskey

import "github.com/effective-security/metrics"

// Descriptions of emited metrics keys
var (
	HTTPReqPerf = metrics.Describe{
		Name:         "http_requests_perf",
		Type:         metrics.TypeSample,
		RequiredTags: []string{"verb", "status", "uri"},
		Help:         "provides quantiles for HTTP request.",
	}
	HTTPReqByRole = metrics.Describe{
		Name:         "http_requests_role",
		Type:         metrics.TypeCounter,
		RequiredTags: []string{"verb", "status", "uri", "role"},
		Help:         "provides counts for HTTP request by role.",
	}

	GRPCReqPerf = metrics.Describe{
		Name:         "rpc_requests_perf",
		Type:         metrics.TypeSample,
		RequiredTags: []string{"api", "status"},
		Help:         "provides quantiles for gRPC request.",
	}
	GRPCReqByRole = metrics.Describe{
		Name:         "rpc_requests_role",
		Type:         metrics.TypeCounter,
		RequiredTags: []string{"api", "status", "role"},
		Help:         "provides counts for gRPC request by role.",
	}

	// StatsVersion is gauge metric for app version
	StatsVersion = metrics.Describe{
		Type: metrics.TypeGauge,
		Name: "version",
		Help: "version provides the deployed version",
		//RequiredTags: []string{},
	}
	// HealthLogErrors is counter metric for log errors
	HealthLogErrors = metrics.Describe{
		Type:         metrics.TypeCounter,
		Name:         "log_errors",
		Help:         "log_errors provides the counter of errors in logs",
		RequiredTags: []string{"pkg", "build"},
	}
)

// Metrics returns slice of metrics from this repo
var Metrics = []*metrics.Describe{
	&HTTPReqPerf,
	&HTTPReqByRole,
	&GRPCReqPerf,
	&GRPCReqPerf,
	&GRPCReqByRole,
	&StatsVersion,
	&HealthLogErrors,
}
