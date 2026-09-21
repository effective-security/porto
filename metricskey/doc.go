// Package metricskey declares the metric descriptors emitted by porto's HTTP
// and gRPC servers (request latency and per-role counters, deployed version,
// logged-error counter). Metrics lists them all so appinit.Metrics can
// register help text with the Prometheus sink.
package metricskey
