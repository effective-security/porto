# FINDINGS

Active, actionable bugs, security issues, and correctness problems.
Completed work and deprecation decisions are omitted.

Use the **ID** when commenting or assigning work. Update **Status** in the
same change as the code or decision, and remove the item when it is complete.
IDs are never reused, so a gap in the numbering only means the item was
resolved and removed.

## Status

| Status         | Meaning                                                |
| -------------- | ------------------------------------------------------ |
| Open           | Not started                                            |
| In Progress    | Being fixed                                            |
| Needs Approval | Behavior or compatibility change that needs a decision |

Type: **security** > **bug** > **race** > **correctness** > **performance** > **docs**.

Severity: **CRITICAL** > **HIGH** > **MEDIUM** > **LOW**.

Line numbers refer to the tree at the time of the audit (2026-09-20) and may
drift; the symbol name is the stable reference.

Fixed during the 2026-09-20 audit and therefore not listed: STS presigned URL
host validation and bounded client in `gserver/roles` (SSRF / identity
forgery), nil `authz` dereference in the gserver gRPC interceptor chain,
missing gRPC status for `httperror.Timeout`, data race on
`restserver.HTTPServer.serving`, inverted expiry test in
`cache.memProv.CleanExpired`, nil config dereference and swallowed sink
error in `appinit.Metrics`, `appinit.Logs` leaving the rotating log file
empty, `tlsconfig.KeypairReloader.Close` deadlock and unlocked timestamp
reads, unreachable "expires_soon" warning, duplicate `metricskey.GRPCReqPerf`
descriptor, all staticcheck SA1019 deprecated calls, and the Go 1.27 gzip
byte-exact test.

## Index

| ID    | Package                                 | Location                                                                 | Title                                                                                                                                        | Type        | Severity | Status         |
| ----- | --------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | -------- | -------------- |
| P-001 | (module)                                | `go.mod` `google.golang.org/grpc v1.84.0`                                | GO-2026-6443: gRPC server panic via missing authority/Host headers                                                                           | security    | HIGH     | Fixed          |
| P-007 | gserver                                 | `serve.go` `configureRateLimiter`                                        | Rate limiter keys on client-controlled `X-Forwarded-For` by default                                                                          | security    | MEDIUM   | Fixed          |
| P-009 | gserver/roles                           | `roles.go` `enforceCSRFCookieAndHeader`                                  | CSRF cookie and header values written into error text and logs                                                                               | security    | LOW      | Open           |
| P-010 | gserver/roles                           | `roles.go` `provider.awsIdentity`                                        | Failed STS lookups are not negatively cached; each bad token repeats the outbound call                                                       | performance | LOW      | Open           |
| P-013 | gserver/roles                           | `roles.go` `IdentityFromContext`                                         | Cookie auth over gRPC skips the CSRF check; HTTP cookie auth silently requires `cookies.csrf`                                                | security    | LOW      | Needs Approval |
| P-014 | gserver/credentials                     | `credentials.go` `perRPCCredential.GetRequestMetadata`                   | Unsynchronized reads of `callerIdentity`/`dpopSigner`; thundering-herd token refresh                                                         | race        | LOW      | Open           |
| P-015 | gserver/credentials                     | `credentials.go` `bundle.NewWithMode`                                    | Returns `(nil, nil)`, violating the `grpccredentials.Bundle` contract                                                                        | correctness | LOW      | Open           |
| P-017 | xhttp/identity                          | `realip.go` `ClientIPFromRequest`                                        | Returns "" when `X-Forwarded-For` holds only private addresses                                                                               | bug         | MEDIUM   | Fixed          |
| P-018 | xhttp/identity, restserver              | `realip.go`, `ctx.go`, `server.go` `GetServerURL`                        | `X-Forwarded-For`, `X-Real-Ip`, `X-Forwarded-Proto` trusted from any client                                                                  | security    | MEDIUM   | Fixed          |
| P-035 | (module)                                | `.github/workflows/unittest.yml`, `coverage.out`                         | Total coverage 83.5% is below the 90% CI gate                                                                                                | docs        | LOW      | Open           |
| P-067 | pkg/appinit                             | `metrics.go` `contextCloser.Close`                                       | CloudWatch `Run` goroutine is never cancelled                                                                                                | bug         | LOW      | Open           |
| P-068 | pkg/appinit                             | `init.go` `CPUProfiler`                                                  | `StartCPUProfile` error ignored; profile file handle never closed                                                                            | bug         | LOW      | Open           |
| P-073 | pkg/appinit/config                      | `config.go` `CloudWatch`                                                 | `add_tags`/`replace_tags` parsed but unused; `AwsEndpoint` untagged; "wait on exist" typo                                                    | docs        | LOW      | Needs Approval |
| P-074 | pkg/tlsconfig                           | `cipher_suites.go`                                                       | Modernization: derive cipher names from `tls.CipherSuites()` and reject insecure ones                                                        | correctness | LOW      | Needs Approval |
| P-076 | gserver                                 | `serve.go` `serveCtx.grpcHandlerFunc`                                    | gRPC-Web gzip chosen by substring match on `Accept-Encoding`; ignores `q=0`                                                                  | correctness | LOW      | Open           |
| P-083 | pkg/retriable                           | `retriable.go` `New`                                                     | `WithTransport` in options silently drops `ClientConfig.TLS`                                                                                 | security    | LOW      | Needs Approval |
| P-084 | restserver, gserver                     | `server.go` `NewMux`, `serve.go` `configureHandlers`                     | HTTP metrics miss identity 401s, gserver 429s and gserver CORS preflights                                                                    | correctness | LOW      | Needs Approval |
| P-085 | restserver/telemetry                    | `response_capture.go` `ResponseCapture`                                  | `ResponseCapture` hides `io.ReaderFrom`, disabling the sendfile path                                                                         | performance | LOW      | Open           |

## Details

### P-001 GO-2026-6443 in google.golang.org/grpc v1.84.0

- Evidence: `govulncheck ./...` reports `gserver/serve.go` `grpcHandlerFunc` calls `grpc.Server.ServeHTTP`, which reaches the vulnerable `transport.http2Server.HandleStreams`.
- Impact: a request without `:authority`/`Host` can panic the gRPC server.
- Fix: upgrade to the first released `google.golang.org/grpc` that contains the fix (only `v1.85.0-dev` pseudo-versions exist as of the audit). Pin a pseudo-version or wait for `v1.85.0`.

### P-007 Rate limiter keyed on `X-Forwarded-For`

- Evidence: when `HeadersIPLookups` is empty tollbooth defaults to `X-Forwarded-For`, `X-Real-IP`, then `RemoteAddr`.
- Impact: without a trusted proxy, clients bypass the limiter by rotating a fake `X-Forwarded-For`.
- Fix: default to `["RemoteAddr"]`; document that header lookups are only safe behind a trusted proxy.
- Resolution: the default limiter keys on the resolved client address. Direct
  requests use the socket peer; trusted proxy requests use the validated XFF
  chain. Explicit `headers_ip_lookups` remains an administrator override.
  The default limiter's `X-Rate-Limit-Request-Remote-Addr` response header
  now carries that client IP instead of the socket peer's `host:port`, and a
  request without a client IP is not limited.

### P-009 CSRF values in error text

- Evidence: `errors.Errorf("CSRF token mismatch: passed '%s', expected '%s'", headerToken, c.Value)`; the error string is logged.
- Impact: CSRF cookie values leak to logs.
- Fix: drop the values from the message.

### P-010 STS lookup failures not cached

- Evidence: `awsIdentity` only caches successful lookups (`p.awsCache.Add` after decoding); the LRU is 100 entries keyed by the full URL.
- Impact: repeated bad tokens each cost an outbound STS call (now bounded by a 10s timeout and 64 KiB body).
- Fix: negatively cache failures for a short TTL.

### P-013 Cookie auth CSRF asymmetry

- Evidence: HTTP path accepts the auth cookie only when `Cookies.CSRF != ""`; the gRPC path (`md["cookie"]`) accepts it with no CSRF check.
- Fix: validate in `New` that `Cookies.Auth` requires `Cookies.CSRF`; check `x-csrf-token` metadata on the gRPC path.

### P-014 `perRPCCredential` races and thundering herd

- Evidence: `rc.callerIdentity` and `rc.dpopSigner` are read without `authTokenMu` while `WithCallerIdentity`/`WithDPoP` write under it; every concurrent RPC with an expired token calls `GetCallerIdentity`.
- Fix: read under `RLock`; use `singleflight` for the refresh.

### P-015 `NewWithMode` returns `(nil, nil)`

- Fix: return an error, or return the receiver.

### P-017 Empty client IP with private-only `X-Forwarded-For`

- Evidence: the `RemoteAddr` fallback only runs when both headers are empty; after the loop finds no public IP the function returns `xRealIP`, which may be "". `realip_test.go` uses `h.Set` in a loop so a comma list is never tested.
- Fix: fall back to the last XFF entry or `RemoteAddr`; fix the test to join the values.
- Resolution: private client addresses are returned from trusted XFF chains;
  malformed or absent values fall back to the socket peer. Tests cover comma
  lists and multiple header lines. Compatibility: a request with an empty
  `RemoteAddr` (in-process `http.NewRequest`) now returns "" instead of the
  server's `netutil.GetLocalIP`, matching `ClientIPFromGRPC` for unknown peers;
  the server's own address is not the caller's.

### P-018 Proxy headers trusted from any client

- Evidence: `ClientIPFromRequest`, `ClientIPFromGRPC`, `createIdentityContext` and `GetServerURL` read `X-Forwarded-*`/`X-Real-Ip` unconditionally; gRPC variants return the raw metadata value.
- Impact: spoofed audit IPs and attacker-chosen scheme in generated URLs.
- Fix: opt-in trusted-proxy CIDR list or `TrustProxyHeaders` flag; validate `X-Forwarded-Proto` against `http`/`https`.
- Resolution: `gserver` and `restserver` now use opt-in proxy CIDRs. HTTP and
  gRPC client IP extraction reject untrusted or malformed forwarding data;
  URL schemes accept only trusted `http` or `https` values.

### P-035 Coverage below CI gate

- Evidence: B06 verification (2026-09-28), `go test -coverpkg=./... -coverprofile=<file> ./...` followed by `go tool cover -func=<file>`, measured 83.5% total; CI `MIN_TESTCOV` is 90. This remains queued in B24.
- Fix: add tests for the untested packages (`pkg/crlcache`, `pkg/streamctx`, `pkg/appinit/config`, `metricskey`, `tests/testutils`) and the paths named in this file.

### P-067 to P-074 remaining LOW items

- P-067: `ctx: context.Background()` and `c.ctx.Done()` in `Close` cancels nothing.
- P-068: `_ = pprof.StartCPUProfile(cpuf)`; closer keeps the file name, not the handle.
- P-073: `AdditionalTags`/`ReplaceTags` unused; `AwsEndpoint` has no tags; `Flags.WaitOnExit` help typo.
- P-074: hand-maintained cipher map including RC4/3DES (the `pkg/transport` keepalive portion was fixed in B15).

### P-076 gRPC-Web gzip ignores quality values

- Evidence: `compress := !isStream && strings.Contains(r.Header.Get(header.AcceptEncoding), header.Gzip)`. `Accept-Encoding: gzip;q=0` and `xgzip` enable compression, and a second `Accept-Encoding` header line is not read. `marshal.WriteJSON` negotiates with `acceptsGzip`, which honors q-values, so the JSON and gRPC-Web paths disagree for the same request.
- Impact: a client that refuses gzip still gets a gzip-encoded gRPC-Web body.
- Fix: export the negotiation from `xhttp/marshal` (for example `marshal.AcceptsGzip(http.Header)`) and call it here; `gserver` may import `xhttp/*`.

### P-083 `WithTransport` option drops `ClientConfig.TLS`

- Evidence: found by the B16 review (2026-09-29). `New` applies `cfg.TLS` as a `WithTLS` option before the caller's options, so `New(ClientConfig{TLS: ...}, WithTransport(t))` returns no error and a client whose transport has none of the configured TLS settings: the configured trusted CA silently becomes the system roots and the client certificate is not sent. The B16 fail-closed rule covers only `WithTLS`/`WithDNSServer` applied to a non-`*http.Transport`.
- Impact: a caller that combines a TLS config file with a custom transport trusts more CAs than configured, without an error.
- Fix (needs a decision): apply `cfg.TLS` to the final transport after the options unless an option called `WithTLS` (failing closed on a non-`*http.Transport`), or return an error when an option replaces the transport of a config with `TLS`.

### P-084 Responses produced outside the metrics handler are not counted

- Evidence: found by the B17 review (2026-09-29). `telemetry.NewRequestMetrics` sits inside `identity.NewContextHandler` in both servers, and in `gserver` also inside the CORS handler and the rate limiter. An identity mapper error (for example `restserver` `Test_Authz` `must_have_TLS`, 401), a `gserver` rate-limit 429 and a `gserver` CORS preflight are answered before the metrics handler runs, so `http_requests_perf` and `http_requests_role` never count them. `restserver` counts its preflights (CORS is inside metrics there), so the two servers differ.
- Impact: dashboards miss authentication failures and throttling, which are the responses an operator most wants to see.
- Fix (needs a decision): move the metrics handler outside identity, CORS and the rate limiter and carry the role back to it (for example in a per-request holder like the route holder, set by `identity.NewContextHandler`), because `NewContextHandler` stores the identity on a new request that an outer handler never sees, so without that every request would be labelled `guest`; or add a separate counter for responses produced before the metrics handler.

### P-085 `ResponseCapture` hides `io.ReaderFrom`

- Evidence: found by the B17 review (2026-09-29). `ResponseCapture` does not implement `io.ReaderFrom`, so `io.Copy` into a response (for example `http.ServeContent` and `http.FileServer`) behind `restserver` or `gserver` uses a buffered copy instead of `*http.response`'s `ReadFrom` (sendfile on Linux, for plaintext listeners only; TLS connections have no sendfile path). Two captures sit in every chain.
- Fix: add `ReadFrom(src io.Reader) (int64, error)` that counts the bytes and delegates to the delegate's `io.ReaderFrom` when it has one, else `io.Copy` with a writer that only exposes `Write`.

## Notes on items needing approval

- P-013: changes observable auth behavior; tests assert the current strings.
- P-073, P-074: public type behavior or config surface.
- P-083: changes which TLS configuration wins, or rejects a combination that is accepted today.
- P-084: changes which responses the HTTP metrics count and the `role` label of rejected requests.
