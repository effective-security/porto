# ROADMAP

Larger changes that go beyond a single defect. Each item names the
`FINDINGS.md` IDs it would retire. Order is a suggestion, not a commitment.

## 1. Trusted-proxy model for client-supplied headers

`xhttp/identity`, `restserver`, `gserver` and the tollbooth rate limiter all
read `X-Forwarded-For`, `X-Real-Ip` and `X-Forwarded-Proto` from any client.
Introduce one opt-in setting (a trusted proxy CIDR list, or a
`TrustProxyHeaders` flag) shared by both servers, default off, and key the
rate limiter on `RemoteAddr` unless it is set. Retires P-007, P-018.

## 2. Server hardening defaults

Neither server sets `ReadHeaderTimeout`, `ReadTimeout` or a cmux read
timeout; TLS handshakes have no deadline; request bodies are unbounded;
the Prometheus endpoint uses `http.ListenAndServe`. Add a `Timeouts`
config block (header, read, idle, handshake) and a body limit wired into
`marshal.DecodeBody`, with conservative defaults and a documented override.
Retires P-005, P-019, P-026, P-054, P-055.

## 3. gRPC-Web CORS parity with REST

gRPC-Web emits its own `Access-Control-*` headers in `grpcHandlerFunc`,
independently of `rs/cors`, and defaults to `*`. Route gRPC-Web through the
same CORS decision as REST (honor `enabled`, merge `exposed_headers`, return
403 on a disallowed origin). Retires P-002, P-011, P-012, P-013.

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

## 6. `pkg/cache` and `pkg/redisclient` semantics

`GetOrSet` should write back with a TTL; memory and Redis `Keys` should
agree on prefix stripping and glob support; the Redis lock should be
owner-bound (token + compare-and-delete script) and the rate limiter
atomic (Lua). Retires P-036, P-043, P-047, P-064.

## 7. `KeypairReloader` without panics or lock-held sleeps

Return errors from `GetCertificate` callbacks when the certificate has
expired, load new keypairs outside the write lock, and stop mutating
`Transport.TLSClientConfig` per request. Retires P-037, P-050, P-051.

## 8. Unenforced `transport.TLSInfo` fields

Either port the etcd SAN/CN checks into the `tlsCheckFunc` chain or delete
`AllowedCN`, `AllowedHostname`, `EmptyCN`, `ServerName`,
`InsecureSkipVerify`, `SkipClientSANVerify`. Retires P-052.

## 9. Route-template metric labels

`telemetry.NewRequestMetrics` labels by raw path. Stash the registered
httprouter pattern in the request context from `Router.Handle` and use it
as the `uri` tag. Retires P-023.

## 10. Coverage and untested packages

Coverage sits at 79.2% against an 80% gate. `pkg/crlcache`,
`pkg/streamctx`, `pkg/appinit/config`, `metricskey`, `tests/testutils` and
`appinit.Metrics` have no tests; `gserver/roles` has no STS tests beyond
URL validation. Retires P-035.

## 11. Follow up after xpki v1.0 upgrade

There are two DPoP follow-ups if those behaviors matter to your deployment:

HTTP proof verification (gserver/roles/roles.go:293) assumes an https origin when the request URL has no scheme. Plain HTTP or a different public origin needs an explicit trusted external URL.

Proof verification (gserver/roles/roles.go:518) and client proof signing (pkg/retriable/retriable.go:983) do not use xpki’s new opt-in replay and access token hash checks. Enabling access token binding would require coordinated client and server changes.

The stricter JWT time, algorithm, and key checks may reject previously accepted tokens; Porto parses tokens supplied by callers and does not issue them here.
