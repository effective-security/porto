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

| ID    | Package                       | Location                                           | Title                                                                       | Type        | Severity | Status |
| ----- | ----------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------- | ----------- | -------- | ------ |
| P-007 | gserver                       | `serve.go` `configureRateLimiter`                  | Rate limiter keys on client-controlled `X-Forwarded-For` by default         | security    | MEDIUM   | Fixed  |
| P-017 | xhttp/identity                | `realip.go` `ClientIPFromRequest`                  | Returns "" when `X-Forwarded-For` holds only private addresses              | bug         | MEDIUM   | Fixed  |
| P-018 | xhttp/identity, restserver    | `realip.go`, `ctx.go`, `server.go` `GetServerURL`  | `X-Forwarded-For`, `X-Real-Ip`, `X-Forwarded-Proto` trusted from any client | security    | MEDIUM   | Fixed  |
| P-035 | (module)                      | `.github/workflows/unittest.yml`, `coverage.out`   | Total coverage 83.5% is below the 90% CI gate                               | docs        | LOW      | Open   |
| P-076 | gserver                       | `serve.go` `serveCtx.grpcHandlerFunc`              | gRPC-Web gzip chosen by substring match on `Accept-Encoding`; ignores `q=0` | correctness | LOW      | Open   |
| P-091 | gserver, restserver/telemetry | `serve.go` `grpcHandlerFunc`, `request_metrics.go` | A panicking REST handler is never counted by the HTTP metrics               | correctness | LOW      | Open   |

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
- Fix: add tests for the untested packages (`pkg/crlcache`, `pkg/streamctx`, `metricskey`, `tests/testutils`) and the paths named in this file.

### P-076 gRPC-Web gzip ignores quality values

- Evidence: `compress := !isStream && strings.Contains(r.Header.Get(header.AcceptEncoding), header.Gzip)`. `Accept-Encoding: gzip;q=0` and `xgzip` enable compression, and a second `Accept-Encoding` header line is not read. `marshal.WriteJSON` negotiates with `acceptsGzip`, which honors q-values, so the JSON and gRPC-Web paths disagree for the same request.
- Impact: a client that refuses gzip still gets a gzip-encoded gRPC-Web body.
- Fix: export the negotiation from `xhttp/marshal` (for example `marshal.AcceptsGzip(http.Header)`) and call it here; `gserver` may import `xhttp/*`.

### P-091 Panicking REST handlers are not counted

- Evidence: found by the B28 review (2026-09-30). `telemetry.NewRequestMetrics` records after the wrapped handler returns, not in a `defer`, so a panic skips the recording. On `gserver` TLS listeners the recover in `grpcHandlerFunc` answers the REST request with 500 outside `configureHandlers`, and the response is not counted (a scratch test with a panicking route got a 500 and no metrics); on `restserver` and the `gserver` plaintext listener, net/http recovers the panic and aborts the connection, which is not counted either.
- Impact: dashboards miss the 500s of crashing handlers, like the early responses P-084 fixed.
- Fix: record in a `defer` of the outermost `NewRequestMetrics` and let the panic continue: a status of 500 when nothing was written yet (or the captured status), skipping `http.ErrAbortHandler`, which is a deliberate abort.
