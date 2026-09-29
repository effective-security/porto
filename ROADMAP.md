# ROADMAP

Larger changes that go beyond a single defect. Each item names the
`FINDINGS.md` IDs it would retire. Order is a suggestion, not a commitment.

## 1. Trusted-proxy model for client-supplied headers

`xhttp/identity`, `restserver`, `gserver` and the tollbooth rate limiter all
read `X-Forwarded-For`, `X-Real-Ip` and `X-Forwarded-Proto` from any client.
Introduce one opt-in setting (a trusted proxy CIDR list, or a
`TrustProxyHeaders` flag) shared by both servers, default off, and key the
rate limiter on `RemoteAddr` unless it is set. Retires P-007, P-018.

## 3. gRPC-Web CORS parity with REST

v0.41 routes gRPC-Web origin checks through `rs/cors` matching, honors
`enabled`, merges `exposed_headers` and returns 403 on a disallowed origin
(formerly P-002, P-011, P-012). Remaining: cookie-authenticated gRPC calls
skip the CSRF check that HTTP cookie auth requires. Retires P-013.

## 4. Replace archived gRPC middleware

`github.com/grpc-ecosystem/go-grpc-middleware` v1 and
`go-grpc-prometheus` are unmaintained. grpc-go provides
`grpc.ChainUnaryInterceptor` / `ChainStreamInterceptor` natively;
Prometheus metrics move to `go-grpc-middleware/v2/providers/prometheus`.
Metric names may change, so this needs a compatibility note.

## 5. Concurrency-safe `pkg/tasks` and `-race` in CI

`pkg/tasks` fails `go test -race`; `Makefile` has `-race` commented out.
Guard task state with a mutex, fix `Stop`, then enable `RACE=true` in the
CI `covtest` step so regressions are caught. Retires P-048, P-049, P-071.

## 9. Route-template metric labels

`telemetry.NewRequestMetrics` labels by raw path. Stash the registered
httprouter pattern in the request context from `Router.Handle` and use it
as the `uri` tag. Retires P-023.

## 10. Coverage and untested packages

B06 verification measured 83.5% coverage against a 90% gate. `pkg/crlcache`,
`pkg/streamctx`, `pkg/appinit/config`, `metricskey` and `tests/testutils`
have no dedicated tests; B06 added Prometheus lifecycle tests in `appinit.Metrics`; `gserver/roles` has no STS tests beyond
URL validation. Retires P-035.

## 11. Follow up after xpki v1.0 upgrade

There are two DPoP follow-ups if those behaviors matter to your deployment:

HTTP proof verification (gserver/roles/roles.go:293) assumes an https origin when the request URL has no scheme. Plain HTTP or a different public origin needs an explicit trusted external URL.

Proof verification (gserver/roles/roles.go:518) and client proof signing (pkg/retriable/retriable.go:1111) do not use xpki’s new opt-in replay and access token hash checks. Enabling access token binding would require coordinated client and server changes.

The stricter JWT time, algorithm, and key checks may reject previously accepted tokens; Porto parses tokens supplied by callers and does not issue them here.

## 12. Native gRPC transport on TLS listeners

On TLS listeners `gserver` serves native gRPC through `http.Server` and
`grpc.Server.ServeHTTP`. That transport reads request data eagerly into an
unbounded buffer, without HTTP/2 flow control, and ignores the gRPC
keepalive settings. v0.41 therefore clears the per-stream `Timeouts.Read`
deadline for native gRPC but keeps `MaxRequestBody` as a per-stream total,
and a stream over it fails with `Unavailable`. Plaintext listeners are only
limited per message by `MaxRecvMsgSize`. To match them, hand TLS connections
that carry `application/grpc` to `grpc.Server.Serve`, using credentials that
report the TLS state of the connection that is already established. The same
listener also carries REST and gRPC-Web, so the design must handle clients
or proxies that send REST and gRPC over one HTTP/2 connection.
