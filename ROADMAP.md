# ROADMAP

Larger changes that go beyond a single defect. Each item names the
`FINDINGS.md` IDs it would retire. Order is a suggestion, not a commitment.

## 1. Trusted-proxy model for client-supplied headers

`xhttp/identity`, `restserver`, `gserver` and the tollbooth rate limiter all
read `X-Forwarded-For`, `X-Real-Ip` and `X-Forwarded-Proto` from any client.
Introduce one opt-in setting (a trusted proxy CIDR list, or a
`TrustProxyHeaders` flag) shared by both servers, default off, and key the
rate limiter on `RemoteAddr` unless it is set. Retires P-007, P-018.

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

## 10. Coverage and untested packages

B06 verification measured 83.5% coverage against a 90% gate. `pkg/crlcache`,
`pkg/streamctx`, `metricskey` and `tests/testutils` have no dedicated
tests; B06 added Prometheus lifecycle tests in `appinit.Metrics` and B21
added `pkg/appinit/config` decoding tests; `gserver/roles` has no STS tests beyond
URL validation. Retires P-035.

## 11. Follow up after xpki v1.0 upgrade

There are two DPoP follow-ups if those behaviors matter to your deployment:

Proof verification in `gserver/roles` builds the expected `htu` from client-supplied values: `IdentityFromRequest` from the request URL or `Host` (https when the URL has no scheme), and `IdentityFromContext` (`grpcDPoPURI`) from the gRPC `:authority`, always https. Plain HTTP, including gRPC-Web on a plain-HTTP listener, or a different public origin needs a trusted origin setting in porto (for example in `jwt_dpop`) that replaces the scheme and host in both paths. xpki's `dpop.VerifyConfig.ExternalURL` is read only by `dpop.VerifyRequestClaims`, so it could cover the HTTP path only if `dpopIdentity` switched to that call; `dpop.VerifyClaims` ignores it.

Proof verification (`gserver/roles` `dpopIdentity`) and client proof signing (`pkg/retriable` `Client.Do`, `gserver/credentials` `perRPCCredential.GetRequestMetadata`) do not use xpki’s new opt-in replay and access token hash checks. Enabling access token binding would require coordinated client and server changes.

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

## 13. Dual certificates for the post-quantum transition

`pkg/tlsconfig` and `pkg/transport` serve one certificate pair. An ML-DSA
pair (xpki v1.1) authenticates TLS 1.3 clients only, and `SetMinVersion`
refuses TLS 1.2 for it, so a server cannot serve TLS 1.2 clients with a
classical certificate and TLS 1.3 clients with an ML-DSA one at the same
time. A second `CertFile`/`KeyFile` pair in `transport.TLSInfo`, selected in
`GetCertificate` with `tls.ClientHelloInfo.SupportsCertificate`, would allow
that, with a second `KeypairReloader` and the same expiry rules. Clients
(`pkg/retriable`, `pkg/redisclient`) have the same single pair for mutual
TLS. Not planned until a deployment needs both.
