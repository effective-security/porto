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
| P-003 | gserver                                 | `serve.go` `serveCtx.serve`, `server.go` `Server.Close`                  | `Close` deadlocks if a listener's `serve` fails before publishing servers                                                                    | bug         | MEDIUM   | Open           |
| P-004 | gserver                                 | `serve.go` `configureListeners`, `server.go` `Server.Close`              | TLS keypair reloader goroutine leaked on `Close`                                                                                             | bug         | MEDIUM   | Open           |
| P-006 | gserver                                 | `serve.go` `configureRateLimiter`                                        | `rate_limit.enabled` without `requests_per_second` blocks nearly all traffic                                                                 | correctness | MEDIUM   | Needs Approval |
| P-007 | gserver                                 | `serve.go` `configureRateLimiter`                                        | Rate limiter keys on client-controlled `X-Forwarded-For` by default                                                                          | security    | MEDIUM   | Fixed          |
| P-009 | gserver/roles                           | `roles.go` `enforceCSRFCookieAndHeader`                                  | CSRF cookie and header values written into error text and logs                                                                               | security    | LOW      | Open           |
| P-010 | gserver/roles                           | `roles.go` `provider.awsIdentity`                                        | Failed STS lookups are not negatively cached; each bad token repeats the outbound call                                                       | performance | LOW      | Open           |
| P-013 | gserver/roles                           | `roles.go` `IdentityFromContext`                                         | Cookie auth over gRPC skips the CSRF check; HTTP cookie auth silently requires `cookies.csrf`                                                | security    | LOW      | Needs Approval |
| P-014 | gserver/credentials                     | `credentials.go` `perRPCCredential.GetRequestMetadata`                   | Unsynchronized reads of `callerIdentity`/`dpopSigner`; thundering-herd token refresh                                                         | race        | LOW      | Open           |
| P-015 | gserver/credentials                     | `credentials.go` `bundle.NewWithMode`                                    | Returns `(nil, nil)`, violating the `grpccredentials.Bundle` contract                                                                        | correctness | LOW      | Open           |
| P-016 | restserver/ready                        | `ready.go` `errUnavailable`; `xhttp/httperror` `Error.WriteHTTPResponse` | Package-level error mutated per request (stale `request_id`, data race)                                                                      | race        | MEDIUM   | Open           |
| P-017 | xhttp/identity                          | `realip.go` `ClientIPFromRequest`                                        | Returns "" when `X-Forwarded-For` holds only private addresses                                                                               | bug         | MEDIUM   | Fixed          |
| P-018 | xhttp/identity, restserver              | `realip.go`, `ctx.go`, `server.go` `GetServerURL`                        | `X-Forwarded-For`, `X-Real-Ip`, `X-Forwarded-Proto` trusted from any client                                                                  | security    | MEDIUM   | Fixed          |
| P-023 | restserver/telemetry                    | `request_metrics.go` `requestMetrics.ServeHTTP`                          | Unbounded metric label cardinality on raw URL path                                                                                           | performance | MEDIUM   | Needs Approval |
| P-024 | restserver/telemetry                    | `response_capture.go` `ResponseCapture`                                  | Hides `http.Hijacker`/`Unwrap` from downstream handlers                                                                                      | correctness | MEDIUM   | Open           |
| P-027 | xhttp/httperror, restserver/authz       | `codes.go` `codeStatus`; `authz.go` `authHandler.ServeHTTP`              | `PermissionDenied` maps to 401; authz denies with 401 instead of 403                                                                         | correctness | LOW      | Needs Approval |
| P-028 | restserver/authz                        | `authz.go` `authHandler.ServeHTTP`                                       | Denial error double-wrapped, duplicating the code in the message and dropping the context                                                    | correctness | LOW      | Needs Approval |
| P-029 | xhttp/httperror                         | `errors.go` `errMsg`                                                     | Panics on a non-string format argument                                                                                                       | bug         | LOW      | Open           |
| P-031 | restserver/telemetry                    | `requestlogger.go` `RequestLogger.ServeHTTP`                             | Divide by zero when granularity is 0                                                                                                         | bug         | LOW      | Open           |
| P-032 | xhttp/marshal, xhttp/identity           | `marshal.go` `WriteJSON`; `ctx.go`                                       | Internal error text echoed to clients in 5xx/401 bodies                                                                                      | security    | LOW      | Needs Approval |
| P-033 | restserver/authz                        | `authz.go` `checkAccess`                                                 | `OPTIONS` bypasses authz even with `OptionsPassthrough`                                                                                      | security    | LOW      | Needs Approval |
| P-035 | (module)                                | `.github/workflows/unittest.yml`, `coverage.out`                         | Total coverage 83.5% is below the 90% CI gate                                                                                                | docs        | LOW      | Open           |
| P-041 | pkg/cache                               | `redis.go` `rsub.ReceiveMessage`                                         | Goroutine leaked per cancelled or timed-out receive                                                                                          | bug         | MEDIUM   | Open           |
| P-042 | pkg/cache                               | `memory.go` `memProv.Publish`                                            | Blocks forever on a subscriber that stopped draining                                                                                         | bug         | MEDIUM   | Open           |
| P-043 | pkg/redisclient                         | `redisclient.go` `TryAcquireRateLimit`                                   | Denied attempts are recorded, starving pollers; read and write are not atomic                                                                | correctness | MEDIUM   | Needs Approval |
| P-044 | pkg/redisclient, pkg/cache              | `redisclient.go` `Key`; `memory.go`, `proxy.go`, `redis.go`              | `path.Join` lets `..` in a key escape the prefix namespace                                                                                   | security    | MEDIUM   | Needs Approval |
| P-045 | pkg/redisclient                         | `redisclient.go` `NewRedisClient`                                        | Redis URL, which may embed a password, logged at INFO                                                                                        | security    | MEDIUM   | Open           |
| P-046 | pkg/retriable                           | `retriable.go` `New`                                                     | `request:` block without `retry_limit` silently disables retries                                                                             | correctness | MEDIUM   | Needs Approval |
| P-047 | pkg/redisclient                         | `redisclient.go` `ReleaseLock`, `TryLock`                                | Lock release is not owner-bound and not atomic                                                                                               | correctness | MEDIUM   | Needs Approval |
| P-052 | pkg/transport                           | `tls.go` `TLSInfo`                                                       | `AllowedCN`, `AllowedHostname`, `EmptyCN`, `ServerName`, `InsecureSkipVerify`, `SkipClientSANVerify` are never enforced                      | security    | MEDIUM   | Needs Approval |
| P-053 | pkg/transport                           | `keepalive_listener.go` `Accept`                                         | `errors.WithStack` on accept errors defeats `Temporary()` retry in net/http and grpc                                                         | bug         | MEDIUM   | Open           |
| P-056 | pkg/retriable                           | `retriable.go` `Do`                                                      | Backoff sleep ignores the request context; drained bodies are not closed                                                                     | correctness | LOW      | Open           |
| P-057 | pkg/retriable                           | `retriable.go` `executeRequest`                                          | `RequestTimeout` cancel func discarded; timers live until the deadline                                                                       | performance | LOW      | Open           |
| P-058 | pkg/retriable                           | `retriable.go` `Policy.ShouldRetry`, `DefaultPolicy`                     | 429 entry in `DefaultPolicy` is unreachable                                                                                                  | correctness | LOW      | Needs Approval |
| P-060 | pkg/retriable                           | `nonce.go` `pushNonce`, `Nonce`                                          | Cache trim drops the newest nonce; `Nonce()` ignores context                                                                                 | bug         | LOW      | Open           |
| P-061 | pkg/retriable                           | `retriable.go` `WithTLS`, `WithDNSServer`                                | Unchecked `*http.Transport` assertion; mutates a caller-supplied transport in place                                                          | bug         | LOW      | Needs Approval |
| P-062 | pkg/redisclient                         | `redisclient.go` `Close`                                                 | Nils the embedded client; children keep using a closed connection; close errors hidden                                                       | bug         | LOW      | Needs Approval |
| P-063 | pkg/redisclient                         | `redisclient.go` `SAddWithEviction`, `HSetWithEviction`                  | Errors ignored; re-adds create duplicate list entries and mis-evict                                                                          | correctness | LOW      | Open           |
| P-064 | pkg/cache                               | `memory.go` `Keys` vs `redis.go` `Keys`                                  | Memory returns prefixed names, Redis strips the prefix; pattern subsets differ                                                               | correctness | LOW      | Needs Approval |
| P-065 | pkg/retriable                           | `retriable.go` `RequestURL`                                              | Byte-offset slicing breaks URLs with userinfo                                                                                                | bug         | LOW      | Open           |
| P-066 | pkg/retriable                           | `storage.go`, `retriable.go`                                             | Archived `go-homedir` import; `WithUserAgent` blocks up to 1s; error bodies buffered unbounded                                               | correctness | LOW      | Open           |
| P-067 | pkg/appinit                             | `metrics.go` `contextCloser.Close`                                       | CloudWatch `Run` goroutine is never cancelled                                                                                                | bug         | LOW      | Open           |
| P-068 | pkg/appinit                             | `init.go` `CPUProfiler`                                                  | `StartCPUProfile` error ignored; profile file handle never closed                                                                            | bug         | LOW      | Open           |
| P-073 | pkg/appinit/config                      | `config.go` `CloudWatch`                                                 | `add_tags`/`replace_tags` parsed but unused; `AwsEndpoint` untagged; "wait on exist" typo                                                    | docs        | LOW      | Needs Approval |
| P-074 | pkg/transport, pkg/tlsconfig            | `keepalive_listener.go`, `cipher_suites.go`                              | Modernization: `SetKeepAliveConfig`; derive cipher names from `tls.CipherSuites()` and reject insecure ones                                  | correctness | LOW      | Needs Approval |
| P-075 | pkg/cache                               | `cache_test.go` `TestProvider/redis` (pub/sub)                           | Flaky under load: Redis `ReceiveMessage` hits a 5s i/o timeout; `require` used inside goroutines                                             | docs        | LOW      | Open           |
| P-076 | gserver                                 | `serve.go` `serveCtx.grpcHandlerFunc`                                    | gRPC-Web gzip chosen by substring match on `Accept-Encoding`; ignores `q=0`                                                                  | correctness | LOW      | Open           |
| P-077 | gserver                                 | `serve.go` `serveCtx.serve` (TLS listener)                               | TLS gRPC client/bidi streams are cut by `Timeouts.Read` (30s) and a cumulative `MaxRequestBody` (10 MiB)                                     | correctness | MEDIUM   | Needs Approval |
| P-078 | gserver, restserver, xhttp/marshal      | `serve.go` `serveCtx.serve`; `server.go` `NewMux`; `limits.go`           | Early 413 from `LimitRequestBody` bypasses CORS, request logging and metrics; gRPC callers get JSON                                          | correctness | LOW      | Open           |
| P-079 | xhttp/httperror                         | `codes.go` `statusCode`                                                  | `request_too_large` (HTTP 413) maps to gRPC `InvalidArgument`, which converts back to HTTP 400                                               | correctness | LOW      | Needs Approval |

## Details

### P-001 GO-2026-6443 in google.golang.org/grpc v1.84.0

- Evidence: `govulncheck ./...` reports `gserver/serve.go` `grpcHandlerFunc` calls `grpc.Server.ServeHTTP`, which reaches the vulnerable `transport.http2Server.HandleStreams`.
- Impact: a request without `:authority`/`Host` can panic the gRPC server.
- Fix: upgrade to the first released `google.golang.org/grpc` that contains the fix (only `v1.85.0-dev` pseudo-versions exist as of the audit). Pin a pseudo-version or wait for `v1.85.0`.

### P-003 `Server.Close` deadlock after a failed `serve`

- Evidence: `serve` returns on `transport.NewTLSListener` error before `close(sctx.serversC)`; `Close` ranges over `serversC` and blocks forever. `Start`'s deferred cleanup only closes the channel when `!serving`, but `serveClients` always returns nil.
- Impact: when TLS listener setup fails at runtime, `Err()` delivers the error and the caller's `Close()` hangs.
- Fix: `defer close(sctx.serversC)` once at the top of `serve` (guarded by `sync.Once`).

### P-004 TLS keypair reloader leaked

- Evidence: `configureListeners` calls `tlsInfo.ServerTLSWithReloader()`, which starts a `tlsconfig.KeypairReloader` ticker goroutine; nothing in gserver calls `tlsInfo.Close()`.
- Impact: one ticker goroutine per `Start`/`Close` cycle.
- Fix: call `tlsInfo.Close()` in `Server.Close` after closing the listeners.

### P-006 `rate_limit.enabled` without `requests_per_second`

- Evidence: `tollbooth.NewLimiter(float64(cfg.RequestsPerSecond), &ops)` with max 0 yields burst 1 that never refills.
- Impact: one request per client key, then 429 forever; no startup validation.
- Fix: return an error from `Start`, or apply a documented default, when `Enabled && RequestsPerSecond <= 0`.

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

### P-016 Shared `errUnavailable` mutated per request

- Evidence: `Error.WriteHTTPResponse` sets `e.RequestID` on the receiver; `ready.go` writes the package-level `errUnavailable` on every not-ready request.
- Impact: the first 503's correlation ID is baked into the global; concurrent first requests race on a package var. Any consumer keeping `httperror.Error` values in package vars has the same hazard.
- Fix: write from a copy (`e2 := *e`) in `WriteHTTPResponse`, or build the error per request in `ready`.

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

### P-023 Metric label cardinality

- Evidence: `HTTPReqPerf.MeasureSince(start, method, status, r.URL.Path)` uses the raw path; only 404s collapse to `unknown`.
- Fix: label with the matched route template or add a path-normalizer option.

### P-024 `ResponseCapture` lacks `Unwrap`/`Hijack`

- Evidence: implements only `Header/Write/WriteHeader/Flush`; inserted twice in every chain.
- Impact: WebSocket upgrades and `http.ResponseController` deadlines are impossible behind restserver.
- Fix: add `Unwrap() http.ResponseWriter`; make `Flush` conditional on the delegate.

### P-027 `PermissionDenied` → 401

- Evidence: `codeStatus[codes.PermissionDenied] = http.StatusUnauthorized`; authz denies an authenticated role with `Unauthorized`.
- Fix: map to 403 and use `httperror.Forbidden` in authz; tests assert the current strings.

### P-028 authz double-wrap

- Evidence: `checkAccess` returns `httperror.Unauthorized(...).WithContext(ctx)`; the handler re-wraps with `httperror.Unauthorized("%s", err.Error())`.
- Fix: `marshal.WriteJSON(w, r, err)` directly.

### P-029 `errMsg` unchecked type assertion

- Evidence: `fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...)`.
- Fix: check the assertion and fall back to `fmt.Sprint`.

### P-031 Granularity divide by zero

- Fix: clamp to `max(1, int64(granularity))` in `NewRequestLogger`.

### P-032 Internal error text echoed

- Evidence: non-`httperror` errors become a 500 whose `message` is `err.Error()`; identity mapper errors are returned verbatim.
- Fix: generic message for 5xx; keep logging the cause.

### P-033 `OPTIONS` bypasses authz

- Evidence: `if r.Method == http.MethodOptions { return nil }` unconditionally.
- Fix: short-circuit only when `Access-Control-Request-Method` is present.

### P-035 Coverage below CI gate

- Evidence: B06 verification (2026-09-28), `go test -coverpkg=./... -coverprofile=<file> ./...` followed by `go tool cover -func=<file>`, measured 83.5% total; CI `MIN_TESTCOV` is 90. This remains queued in B24.
- Fix: add tests for the untested packages (`pkg/crlcache`, `pkg/streamctx`, `pkg/appinit/config`, `metricskey`, `tests/testutils`) and the paths named in this file.

### P-041 Redis subscription goroutine leak

- Evidence: `ReceiveMessage` spawns a goroutine sending on an unbuffered channel and selects on a 1s timer; returning through the timer branch leaves the sender blocked forever.
- Fix: buffer the channel (size 1) and select on `ctx.Done()`.

### P-042 Memory `Publish` blocks

- Evidence: unconditional `s.ch <- message` inside `subs.Range`; buffer is 10; `ctx` ignored.
- Fix: non-blocking send with drop or `ctx.Done()`.

### P-043 Rate limiter starvation and non-atomic window

- Evidence: `Pipeline()` (not `TxPipeline`) does `ZCard` then unconditional `ZAdd`/`Set`/`Expire`; allowed only when the count is 0.
- Impact: a caller polling faster than the window is denied forever; two concurrent callers can both win.
- Fix: `ZAdd` only when allowed, inside a Lua script or `WATCH` transaction.

### P-044 Key namespace escape

- Evidence: `path.Join(c.prefix, key)` cleans `..`, so `Key("../other/x")` under `/tenant-a/` yields `/other/x`. Same pattern in `pkg/cache`.
- Fix: reject `..` or concatenate without cleaning.

### P-045 Redis URL logged

- Evidence: `logger.KV(xlog.INFO, "redis", cfg.Server)` where `Server` may be `redis://user:password@host/db`.
- Fix: log `options.Addr` after `ParseURL`.

### P-046 `request:` without `retry_limit`

- Evidence: `pol.TotalRetryLimit = cfg.Request.RetryLimit` overwrites the default 5 with 0 whenever the block is present.
- Fix: `cmp.Or(cfg.Request.RetryLimit, pol.TotalRetryLimit)` or a pointer field.

### P-047 Lock release not owner-bound

- Evidence: `TryLock` stores a timestamp value; `ReleaseLock` does `Exists` then `Del` without comparing the value.
- Fix: return a token from `TryLock` and release with a compare-and-delete script.

### P-052 Unenforced `TLSInfo` fields

- Evidence: the six fields are declared and documented but never read; the SAN check in `listener_tls.go` is commented out.
- Fix: implement the checks in the `tlsCheckFunc` chain or remove the fields.

### P-053 Wrapped accept errors

- Evidence: `return nil, errors.WithStack(err)`; `net/http` and grpc use a plain type assertion for `Temporary()`.
- Impact: a transient `EMFILE` stops the server instead of backing off.
- Fix: return `err` unwrapped.

### P-056 to P-066 retriable / redisclient / cache LOW items

- P-056: `time.Sleep(sleepDuration)` ignores `ctx.Done()`; `consumeResponseBody` only drains.
- P-057: `ctx, _ = c.ensureContext(...)` drops the cancel func.
- P-058: `ShouldRetry` returns `LimitExceeded` for 429 before consulting `p.Retries`.
- P-060: `c.nonces = c.nonces[nonceCacheLimit/2 : count-1]` drops the freshest nonce; `Nonce()` uses `context.Background()`.
- P-061: `c.httpClient.Transport.(*http.Transport)` unchecked; `http.DefaultTransport` mutated when passed in.
- P-062: `Close` sets `c.Client = nil` and always returns nil.
- P-063: `length, _ := c.LLen(...)`, `oldest, _ := c.LPop(...)`, `_ = c.SRem(...)`; `RPush` appends duplicates.
- P-064: memory `Keys` appends the full name; Redis `Keys` trims the prefix; memory supports only a trailing wildcard.
- P-065: `path := rawURL[len(host):]` with `host := u.Scheme + "://" + u.Host`.
- P-066: `go-homedir` vs `resolve.ExpandPath`; `netutil.WaitForNetwork(time.Second)` in a constructor; `bodyCopy` of error responses unbounded.

### P-067 to P-074 remaining LOW items

- P-067: `ctx: context.Background()` and `c.ctx.Done()` in `Close` cancels nothing.
- P-068: `_ = pprof.StartCPUProfile(cpuf)`; closer keeps the file name, not the handle.
- P-073: `AdditionalTags`/`ReplaceTags` unused; `AwsEndpoint` has no tags; `Flags.WaitOnExit` help typo.
- P-074: `SetKeepAlive`+`SetKeepAlivePeriod`; hand-maintained cipher map including RC4/3DES.

### P-075 Flaky Redis pub/sub test

- Evidence: one run of `go test ./...` (all packages in parallel, Redis in testcontainers) failed `TestProvider/redis` at `cache_test.go:270` with `read tcp [::1]:40600->[::1]:32789: i/o timeout`; the test passes in isolation and on rerun. The receiving goroutines call `require.NoError`, which invokes `FailNow` from a non-test goroutine.
- Fix: use `assert` plus an error channel in the goroutines; give the subscription time to be established before `Publish` (or retry the publish); consider a longer context deadline for the container-backed subtest. Related to P-041.

### P-076 gRPC-Web gzip ignores quality values

- Evidence: `compress := !isStream && strings.Contains(r.Header.Get(header.AcceptEncoding), header.Gzip)`. `Accept-Encoding: gzip;q=0` and `xgzip` enable compression, and a second `Accept-Encoding` header line is not read. `marshal.WriteJSON` negotiates with `acceptsGzip`, which honors q-values, so the JSON and gRPC-Web paths disagree for the same request.
- Impact: a client that refuses gzip still gets a gzip-encoded gRPC-Web body.
- Fix: export the negotiation from `xhttp/marshal` (for example `marshal.AcceptsGzip(http.Header)`) and call it here; `gserver` may import `xhttp/*`.

### P-077 TLS gRPC streams bounded by HTTP read and body limits

- Evidence: on TLS listeners native gRPC is served through `http.Server` and `grpcHandlerFunc`, wrapped by `marshal.LimitRequestBody` and `Timeouts.ApplyHTTP`. net/http's HTTP/2 server arms `ReadTimeout` per stream (`stream.onReadTimeout` closes the request body with `os.ErrDeadlineExceeded`), and `http.MaxBytesReader` counts every message on the stream.
- Impact: with defaults, a client-streaming or bidi RPC that is still sending after 30s, or that sends more than 10 MiB in total, fails on TLS listeners, while the same RPC on a plaintext (h2c) listener is limited only per message by `MaxRecvMsgSize`. The B06 decision records this trade-off ("raise or disable read/body limits for long request streams").
- Fix (needs approval): in `grpcHandlerFunc`, for native gRPC (`application/grpc`, not gRPC-Web) clear the stream read deadline with `http.NewResponseController(w).SetReadDeadline(time.Time{})` and skip the HTTP body limit, relying on gRPC keepalive and `MaxRecvMsgSize`.

### P-078 Early 413 bypasses the handler chain

- Evidence: `LimitRequestBody` rejects a known oversized `Content-Length` before calling next. In `gserver` it wraps the rate limiter, correlation, CORS, identity, metrics and logging; in `restserver.NewMux` it sits outside identity, metrics and logging, and CORS lives in the router.
- Impact: browsers see a CORS failure instead of HTTP 413; the rejection has no correlation ID (gserver) and is absent from request logs and metrics; gRPC and gRPC-Web callers receive a JSON body without `grpc-status`.
- Fix: keep `MaxBytesReader` at the outer layer but move the `Content-Length` rejection inside the telemetry/CORS chain, or answer gRPC content types with a gRPC status.

### P-079 `request_too_large` gRPC mapping

- Evidence: `RequestTooLarge` now returns HTTP 413, but `statusCode[CodeRequestTooLarge]` is `codes.InvalidArgument`; `NewFromPb` converts that back with `HTTPStatusFromRPC` to 400 `bad_request`.
- Impact: an oversized request reported over gRPC reaches REST clients of a proxying service as 400, not 413.
- Fix (needs approval): map `CodeRequestTooLarge` to `codes.ResourceExhausted` (the code grpc-go uses for oversized messages) and decide the HTTP status for that code.

## Notes on items needing approval

- P-006: new rate-limit defaults that deployments may need to configure.
- P-013, P-027, P-028, P-032, P-033: change observable auth or error behavior; tests assert the current strings.
- P-023: changes metric label semantics for dashboards.
- P-046, P-058, P-061, P-062: currently silent or panicking paths become errors or warnings.
- P-043, P-047: rate limiter and lock semantics change under concurrency.
- P-044, P-064: key layout changes for keys containing `..`, `//` or a prefix.
- P-052, P-073, P-074: public type behavior or config surface.
- P-077: changes the recorded B06 network-limit decision for TLS gRPC streams.
- P-079: changes the gRPC code clients observe for oversized requests.
