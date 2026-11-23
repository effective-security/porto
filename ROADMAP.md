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

## 14. Explicit gRPC header list size for ML-DSA credentials

An ML-DSA DPoP request carries an access token and a proof of about 5.9 KB
each with ML-DSA-44 and 11 KB each with ML-DSA-87 (xpki v1.1.322; see the
1.1 release notes). `gserver` and `pkg/rpcclient` set no
`grpc.MaxHeaderListSize` / `grpc.WithMaxHeaderListSize`, so they rely on
grpc-go's default, 16 MiB today. grpc-go plans to lower it to 8 KB
(`GRPC_GO_EXPERIMENTAL_ENABLE_8KB_DEFAULT_HEADER_LIST_SIZE`, off by default
in v1.86.0-dev), and its client already logs a WARNING for a call whose
headers exceed 8 KB when the server announces a limit. With the 8 KB
default a native `grpc.Server` (the `gserver` plaintext listeners, or a
grpc-go server that `rpcclient` calls) rejects every ML-DSA DPoP call; TLS
listeners serve gRPC through `http.Server` (item 12), whose limit is
`MaxHeaderBytes` (1 MiB). Set an explicit server limit, configurable in
`gserver.Config`, before grpc-go flips the default, and a matching client
limit in `rpcclient.Config` for large response headers.

## 15. Move to xpki v2

xpki v2 (module `github.com/effective-security/xpki/v2`, see its
`Documentation/RELEASE_NOTES_2.0.md`) asks porto to move first: porto's
exported API uses xpki types (`jwt.Parser`, `jwt.Signer`, `jwt.MapClaims`
and `jwt.Revocation` in `gserver`, `gserver/roles`, `xhttp/identity`,
`pkg/revocation` and `tests/mockappcontainer`; `dpop.Signer` in
`gserver/credentials`), so an application moves all of its xpki imports in
the release in which it takes the porto built on v2. Checked on 2026-11-23
against v2.0.330 in a scratch worktree: rewriting the imports was enough,
`go build`, `go vet` and `go test -short ./...` pass (with the
`TestNewKeyInfo` fix of the 1.1 release notes); the Redis-backed tests were
not run. No logger namespace string names an xpki path. Decide the porto
version that takes it, since it breaks every consumer's build.

After the move, porto can adopt the v2 DPoP options, which item 11 needs:
`dpop.NewSharedReplayCache` over a `ReplayStore` (one `SET NX PX`, which
`pkg/redisclient` can provide) for replay detection across `gserver`
instances, and server nonces (`VerifyConfig.NonceSource`), which require
`pkg/retriable` and `gserver/credentials` to answer `use_dpop_nonce` by
signing the proof again with the `DPoP-Nonce` value; they call
`dpop.ForRequest` without a nonce today.
