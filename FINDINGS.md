# FINDINGS

Open bugs, security issues, and correctness problems. Resolved items are
removed; public behavior changes are recorded in
[the 1.0 release notes](Documentation/RELEASE_NOTES_1.0.md).

Use the **ID** when commenting or assigning work. Remove an item only when every
part is resolved. Compatibility decisions are tracked in [PLAN.md](PLAN.md).
IDs are never reused, so a gap in the numbering only means the item was
resolved and removed.

Type: **security** > **bug** > **race** > **correctness** > **performance** > **docs**.

Severity: **CRITICAL** > **HIGH** > **MEDIUM** > **LOW**.

Line numbers may drift; the symbol name is the stable reference.

## Index

| ID    | Package                                    | Location                                                                                    | Title                                                                                  | Type        | Severity | Status         |
| ----- | ------------------------------------------ | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------- | -------- | -------------- |
| P-101 | gserver                                    | `server.go` `stopServers`                                                                   | `Close` leaves plaintext HTTP keep-alive connections serving                           | bug         | MEDIUM   | Open           |
| P-093 | pkg/rpcclient                              | `client.go` `newClient`                                                                     | `New` panics on a stored DPoP key that holds only a public key                         | bug         | LOW      | Open           |
| P-094 | pkg/redisclient                            | `marshal.go` `UnmarshalStringCmd`                                                           | Command error ignored for a `*string` target                                           | bug         | LOW      | Open           |
| P-096 | pkg/retriable                              | `storage.go` `ListKeys`                                                                     | Listing stops at the first unreadable sub-folder without an error                      | bug         | LOW      | Open           |
| P-102 | gserver                                    | `server.go` `stopServers`, `serve.go` `grpcHandlerFunc`                                     | A gRPC stream that `Close` stops on a TLS listener ends with a malformed HTTP response | bug         | LOW      | Open           |
| P-103 | pkg/rpcclient                              | `client.go` `dial`                                                                          | A canceled `Context` is reported as a dial timeout                                     | bug         | LOW      | Open           |
| P-076 | gserver                                    | `serve.go` `serveCtx.grpcHandlerFunc`                                                       | gRPC-Web gzip chosen by substring match on `Accept-Encoding`; ignores `q=0`            | correctness | LOW      | Open           |
| P-095 | pkg/redisclient, pkg/cache                 | `redisclient.go` `Get`, `HGet`, `IsNotFoundError`; `cache.go` `IsNotFoundError`, `GetOrSet` | `ErrNotFound` returned bare and matched by message text                                | correctness | LOW      | Open |
| P-098 | gserver, xhttp/identity, xhttp/correlation | `logs.go` `logRequest`, `ctx.go`, `correlation.go`                                          | Plain gRPC errors and handler panics reach clients as Unknown, metrics as Internal     | correctness | LOW      | Open           |
| P-099 | gserver                                    | `logs.go` `newLogUnaryInterceptor`, `serve.go` `grpcServer`                                 | gRPC metrics miss calls rejected by request validation                                 | correctness | LOW      | Open           |
| P-100 | gserver                                    | `serve.go` `serveCtx.grpcHandlerFunc`                                                       | REST panic recovery on TLS listeners corrupts started responses and swallows aborts    | correctness | LOW      | Open           |
| P-104 | pkg/redisclient                            | `redisclient.go` `ZAdd`, `ZIncrBy`, `ZRem`, `ZRemRangeByRank`, `SIsMember`                  | Unwrapped go-redis errors and a misformatted member in errors                          | correctness | LOW      | Open           |
| P-097 | pkg/retriable                              | `storage.go` `SaveAuthToken`                                                                | Comment documents a `token_type` field that `ParseAuthToken` ignores                   | docs        | LOW      | Open           |

## Details

### P-076 gRPC-Web gzip ignores quality values

- Evidence: `compress := !isStream && strings.Contains(r.Header.Get(header.AcceptEncoding), header.Gzip)`. `Accept-Encoding: gzip;q=0` and `xgzip` enable compression, and a second `Accept-Encoding` header line is not read. `marshal.WriteJSON` negotiates with `acceptsGzip`, which honors q-values, so the JSON and gRPC-Web paths disagree for the same request.
- Impact: a client that refuses gzip still gets a gzip-encoded gRPC-Web body.
- Fix: export the negotiation from `xhttp/marshal` (for example `marshal.AcceptsGzip(http.Header)`) and call it here; `gserver` may import `xhttp/*`.

### P-093 `rpcclient.New` panics on a public-only DPoP key

- Evidence: `newClient` calls `dpop.NewSigner(k.Key.(crypto.Signer))` without checking the assertion, and `dpop.LoadKey` accepts a public JWK. Saving `jose.JSONWebKey{Key: priv.Public()}` under the key's thumbprint and calling `New` with TLS and `AuthToken{DpopJkt: jkt}` panics with `interface conversion: *ecdsa.PublicKey is not crypto.Signer: missing method Public`.
- Impact: a damaged or wrong key file crashes the caller; library code must return an error.
- Fix: check the assertion and return an error, as `pkg/retriable` `SetAuthorization` does; add a public-key case to `TestNewRejectsAuthToken`.

### P-094 `UnmarshalStringCmd` ignores the command error for `*string`

- Evidence: For a `*string` target the function sets `*t = val.Val()` and returns nil even when the command failed; `*[]byte` and JSON targets return `failed to get key: ...`. `UnmarshalStringCmd(redis.NewStringResult("", redis.Nil), new(string))` returns nil.
- Impact: `Get` checks the error first, but a direct caller reads a missing key or a failed command as `""` without an error.
- Fix: check `val.Err()` once at the top and wrap it.

### P-095 `ErrNotFound` returned bare and matched by message text

- Evidence: `redisclient` `Get` and `HGet` and the `cache` memory and Redis providers' `Get` return `ErrNotFound` itself; AGENTS.md requires wrapping sentinels so the stack is kept. Both `IsNotFoundError` functions (`redisclient`, `cache`) compare with `err == ErrNotFound` next to their `errors.Is` check, and also report any error whose message contains "not found" (documented, and pinned by `client_errors_test.go`). `cache.GetOrSet` uses that check to decide on a miss, so a provider error that mentions "not found" makes it call the getter and overwrite the cached value.
- Impact: no stack on not-found errors; `IsNotFoundError` is true for unrelated errors, and `GetOrSet` can overwrite a value after such an error. Wrapping is a compatibility change for callers that compare with `==`, and dropping the message match for callers that rely on it.
- Fix: return `errors.WithStack(ErrNotFound)` (or a message wrap) and reduce both `IsNotFoundError` functions to `errors.Is`; note both changes in the release notes.

### P-096 `ListKeys` stops at the first unreadable sub-folder

- Evidence: The `filepath.Walk` callback returns its `err` for a sub-folder whose entries cannot be read, so the walk stops there and keys in entries that sort after it are left out, while `ListKeys` returns nil. A folder holding `a/` (mode 000) and `z/<thumbprint>.jwk` lists no keys. The doc says unreadable keys are skipped.
- Impact: a key listing silently shows too few keys.
- Fix: in the callback, skip errors below the root (`filepath.SkipDir` for a directory, nil otherwise) and keep logging them at DEBUG; keep the documented empty list for a missing or unreadable root folder.

### P-097 `SaveAuthToken` documents an ignored `token_type`

- Evidence: The `SaveAuthToken` comment lists `token_type={Bearer|DPoP}` in the stored form, and the `AuthToken.TokenType` comment says it is "Bearer" (default) or "DPoP", but `ParseAuthToken` ignores `token_type`; only `dpop_jkt` selects DPoP, so a stored `token_type=DPoP` without `dpop_jkt` is sent as `Bearer`.
- Fix: correct both comments, or have the parser honor `token_type`.

### P-098 gRPC error codes: Unknown for clients, Internal in metrics

- Evidence: `logRequest` labels any error that is neither an `httperror` nor a gRPC status `codes.Internal` (with a type switch rather than `errors.As`), while grpc-go sends such an error to the client as `codes.Unknown`. The unary interceptors of `xhttp/identity` (`NewAuthUnaryInterceptor`) and `xhttp/correlation` recover handler panics into a plain `errors.New("unhandled exception")`, so a panicking handler reaches the client as `Unknown`, and `panicInterceptor`'s `Internal` is reached only for panics in `Validate`.
- Impact: the gRPC metrics and logs disagree with the code the client receives; dashboards count `Internal` for calls that clients see as `Unknown`.
- Fix: return `httperror.NewGrpcFromCtx(ctx, codes.Internal, "unhandled exception")` from those recovers, and label plain errors with `status.Code(err)` (`Unknown`), using `errors.As` for the `httperror` types.

### P-099 gRPC metrics miss validation rejections

- Evidence: `grpcServer` chains `panicInterceptor`, `NewRequestValidationUnaryInterceptor`, then the correlation and log interceptors, so a request that fails `Validate` (or panics in it) returns before `newLogUnaryInterceptor` and records no `rpc_requests_*`. The log interceptor also registers its recording `defer` after the handler returned, so a panic escaping the inner interceptors would skip it (today the identity interceptor recovers handler panics first).
- Impact: invalid requests are invisible in the gRPC metrics, unlike REST 400s.
- Fix: run the log interceptor before validation (after panic recovery) and record in a `defer` registered before the handler call, as the HTTP metrics handler does.

### P-100 REST panic recovery on TLS listeners

- Evidence: The `recover` in `grpcHandlerFunc` answers every REST panic with `http.Error(w, "unhandled exception", 500)`. When the handler had already sent a status or body, net/http ignores the 500, appends `unhandled exception\n` to the partial body and ends the response normally, so the client cannot tell that it was cut short (net/http on plaintext listeners and `restserver` abort the connection instead). `http.ErrAbortHandler` is answered the same way and logged with a stack, although net/http treats it as a silent abort.
- Impact: truncated REST responses on TLS listeners look complete; a deliberate abort (for example from `httputil.ReverseProxy`) becomes a logged 500. The HTTP metrics already record the status the handler sent.
- Fix: re-panic `http.ErrAbortHandler`, and abort (panic with `http.ErrAbortHandler` after logging) instead of writing a 500 when the response was already started; tracking that needs a small writer wrapper or the metrics `ResponseCapture`.

### P-101 `Close` leaves plaintext HTTP keep-alive connections serving

- Evidence: For a plaintext listener `stopServers` calls `grpc.GracefulStop` and calls `http.Server.Shutdown` only when `Timeout.Request` expires first. Closing the root listener stops new connections, but the HTTP server keeps serving its open keep-alive connections: a client that made one request before `Close` gets a second response on the same connection after `Close` returned (a new connection is refused). `teardown` has already closed the services by then.
- Impact: REST handlers can run after `Close` returned, against closed services, until the client or the idle timeout closes the connection. Because `Close` drains gRPC calls, drained gRPC handlers on every listener also run against closed services for up to `Timeout.Request`.
- Fix: shut down the plaintext HTTP server with the same context as the gRPC graceful stop (`http.Server.Shutdown` drains active requests and closes idle connections), and decide whether services close after the servers stopped; closing them first may be what ends long-lived streams today.

### P-102 TLS gRPC streams stopped by `Close` end with a malformed response

- Evidence: On a TLS listener gRPC runs through `grpc.Server.ServeHTTP` behind `http.Server`; when `Close` stops a stream that outlived `Timeout.Request` (`http.Shutdown`, then `grpc.Stop`), the client receives `Unknown: unexpected HTTP status code received from server: 200 (OK); malformed header: missing HTTP content-type` instead of `Unavailable`.
- Impact: clients cannot tell a server shutdown from a protocol error and may not retry.
- Fix: stop the gRPC server before (or while) the HTTP server shuts down, so the ServeHTTP transport writes its status, and check the code a client gets in the TLS case of `TestCloseStopsStreamsAfterRequestTimeout`.

### P-103 A canceled `Context` is reported as a dial timeout

- Evidence: With `DialTimeout` set, `dial` waits with `WaitForStateChange(dctx, ...)` and, when that fails, returns `failed to connect to "<target>" within <DialTimeout>` without `dctx.Err()`. A `Context` that was already canceled reports a timeout that never happened (for example "within 1h0m0s"), and `errors.Is(err, context.Canceled)` is false.
- Impact: callers cannot tell cancellation from an unreachable server.
- Fix: wrap `dctx.Err()` (`errors.Wrapf(dctx.Err(), "failed to connect to %q", target)`), so `errors.Is` sees `context.Canceled` or `context.DeadlineExceeded`.

### P-104 `redisclient` errors returned unwrapped or misformatted

- Evidence: `ZAdd`, `ZIncrBy`, `ZRem` and `ZRemRangeByRank` return go-redis errors unwrapped, as their comments document, against the AGENTS.md wrapping rule (`client_errors_test.go` pins it); `SIsMember` formats its `member any` with `%s`, so an int member prints as `%!s(int=1)`.
- Impact: errors without stack or key context; garbled messages.
- Fix: wrap with the key, as the other wrappers do, and format members with `%v`; update the comments and the test table.
