// Package ready provides an http.Handler wrapper that gates requests on a
// readiness check. While ServiceStatus.IsReady reports false every request
// is answered with a JSON 503 "not_ready" error instead of reaching the
// delegate handler.
//
//	h := ready.NewServiceStatusVerifier(server, next)
//
// restserver uses it so that a server whose services are still initialising
// (or that has stopped serving) reports unavailable to load balancers.
package ready
