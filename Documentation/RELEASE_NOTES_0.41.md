# porto v0.41 release notes

## Major fixes

### Security

- gRPC-Web CORS now requires an enabled `cors` block and an explicit allowed origin. For both REST and gRPC-Web, an enabled CORS block with an empty origin list now allows none; set `allowed_origins: ["*"]` to retain the old wildcard behavior (and `enabled: true` if enabling gRPC-Web CORS). `Start` now returns an error when an enabled `cors` block combines `allowed_origins: ["*"]` with `allow_credentials: true`; credentialed CORS needs explicit origins or origin patterns. While `cors` is enabled, `Start` also rejects `Access-Control-*` names in `http_headers`; move those settings into the `cors` block. Disallowed gRPC-Web POSTs receive HTTP 403; disallowed preflights receive no allow-origin header. REST requests from disallowed origins still reach their handlers without CORS headers, so REST CORS is not CSRF protection. Configured exposed headers are preserved without duplicate names.

- B10: `marshal.WriteJSON` no longer echoes the text of plain or gRPC-status errors that become 5xx responses; clients receive the generic HTTP status text (for example `Internal Server Error`) and the original error is logged as the cause with the caller's file and line. Identity mapper failures are answered with a generic `invalid identity` 401 (`Unauthenticated` over gRPC); a mapper can still return an `*httperror.Error` to send a deliberate message. `restserver/authz` no longer skips `OPTIONS` requests: preflight headers are caller-controlled, so CORS preflights are answered by the CORS middleware, which `restserver.NewMux` now places outside authz (gserver already did), and every other `OPTIONS` request, including passed-through preflights, is authorized like any method. Denied and not-ready REST responses now carry CORS headers.

- Redact credential headers from retriable HTTP client debug dumps. Token and DPoP key writes now use private temporary files and replace existing credential paths atomically; newly created credential folders use mode `0700`.

### Concurrency, deadlocks and panics

- TLS certificate reloads now load files outside the handshake lock. The reloading HTTP transport keeps one TLS config and selects the current client certificate for each handshake; it clones a supplied `http.Transport` and closes idle connections after rotation and on `Close`.

- Synchronize retriable client setters and token refresh; missing or public-only DPoP signing keys now return errors.

- Make discovery registration and lookup safe for concurrent use; nil services now return an error, and iteration callbacks may register services.

- `httperror.Error.WriteHTTPResponse` and `ManyError.WriteHTTPResponse` no longer modify the error they write, so `Error` values can be shared across requests, and `ManyError` releases its lock before writing; the readiness 503 is built per request and always carries the current `request_id`. `httperror.Wrap` no longer panics when the first message value is not a string.

- Synchronize scheduler and task state, and make repeated `Stop` calls safe. A stopped scheduler can be restarted.

- `tasks.Scheduler.Stop` no longer lets the scheduler dispatch a task after it returned: a tick that was already due when `Stop` closed the run could still dispatch tasks. Dispatch now re-checks the scheduler state under its lock and marks a dispatched task running before `Stop` can return, so every run dispatched before `Stop` is already counted by `RunCount` and reported by `Task.IsRunning` until it finishes (its callback may still begin executing just after `Stop` returned). This holds for tasks created by `tasks.New` and `tasks.NewTask*`; the scheduler calls `Run` of a custom `Task` implementation on a new goroutine, so such a run may begin, and become visible, after `Stop` returned.

- B11: `cache` subscriptions no longer leak a goroutine per cancelled or timed-out `ReceiveMessage`, and an abandoned receive no longer consumes the next published message. Redis subscriptions read through go-redis `PubSub.Channel`, which also reconnects and resubscribes after connection loss. Memory `Publish` no longer blocks on a subscriber that stopped draining. `ReceiveMessage` now returns as soon as its context is done (previously polled once per second) and returns `cache.ErrClosed` after `Close`, which is idempotent and unblocks a pending receive.

- B07: `gserver.Server.Close` no longer blocks when a listener's setup failed after `Start`; `serve` starts no server until its TLS listener is ready and always closes the channel `Close` waits on. `Close` now stops the TLS certificate reloader, which previously leaked one goroutine per `Start`/`Close` cycle, and runs its teardown once: services are closed once, and a repeated or concurrent `Close` returns after the first teardown has finished (previously a second call closed the services again). A failed `Start` now releases everything on every error path: the reloader is stopped, services created by earlier factories are closed when a later factory fails or is missing, and the cleanup no longer depends on a shadowed error variable. `configureListeners` now really closes the listeners it opened before a later listen URL failed (its previous deferred cleanup read a result that the error return had already reset, so the first listener stayed bound) and stops the reloader it started.

### Correctness and interoperability

- Return REST server HTTP bind errors from `StartHTTP`, support `Config()` and IPv6 bind addresses (`HostName()` returns IPv6 hosts without brackets; `GetServerURL` and `GetServerBaseURL` add them), and make `StopHTTP` safe before start and on repeated calls.

- Route `unix:///path` and `unixs:///path` gRPC client endpoints through the Unix socket resolver without appending a TCP port.

- Sign a fresh DPoP proof for each retry attempt.

- Forward a normalized correlation ID from HTTP requests to gRPC metadata, including the `x-request-id` alias when present.

- Honor gzip quality values for JSON responses, skip compression below 1 KiB, and add `Vary: Accept-Encoding`. Compressed JSON and unary gRPC-Web responses now reuse gzip writers.

- `cache.GetOrSet` now stores a successful getter result using the provider's default TTL, reports invalid getter types without panicking, and returns cache write errors.

### Tests and tooling

## New features and behaviour

- B06: shared `xhttp/limits` defaults bound HTTP header reads (10s), whole-request reads (30s), idle keepalive connections (60s), cmux detection and eager TLS handshakes (10s). Header deadlines follow native net/http semantics; HTTP/2 has no per-stream header deadline. Request bodies default to 10 MiB, including standalone `marshal.DecodeBody`. Unknown-length bodies and trailing bytes are bounded too; `RequestTooLarge` now returns HTTP 413. `marshal.LimitRequestBody` writes no response: a known oversized body fails on its first read, so the 413 from `DecodeBody` carries CORS and correlation headers and appears in request logs and metrics. Native gRPC streams on TLS listeners are exempt from the read deadline, so long-lived client and bidi streams are not cut after 30s.
- B11: cache pub/sub delivery is at most once and `Publish` never waits for a subscriber: each subscription buffers 100 undelivered messages (previously 10 for memory); the memory provider drops messages for a full subscriber and Redis follows the go-redis channel policy (a message is dropped after its reader waited one minute). Redis `Subscribe` waits for the server to confirm the subscription, bounded by the context (otherwise by the go-redis dial timeout plus 10s), so a message published after `Subscribe` returns is delivered; a subscription that could not be established returns the wrapped error from `ReceiveMessage` (the context error when the wait was cancelled), and `Publish` errors name the channel.
- Prometheus binds synchronously, returns bind errors without terminating the process, and returns a closer that shuts down its HTTP endpoint. Its endpoint also uses the shared read/body limits.

## Breaking changes: what clients must change

- B06: raise or disable read/body limits for large uploads and long request streams using `gserver.Config.Timeouts`/`MaxRequestBody`, REST `WithTimeouts`/`WithMaxRequestBody`, or Prometheus `timeouts`/`max_request_body`. Zero selects defaults and negative values disable individual limits. `restserver.MaxRequestSize` is now enforced and is 10 MiB (previously an advisory 64 MiB). Native plaintext gRPC retains per-message limits; TLS gRPC/gRPC-Web request streams receive HTTP body limits, and a native gRPC stream on TLS fails with `Unavailable` after `max_request_body` bytes in total. Handlers that read bodies without `DecodeBody` must map `*http.MaxBytesError` themselves; a known oversized body is no longer answered with 413 before the handler runs. Native net/http TLS handshakes use the smaller positive header/read deadline; `Handshake` configures cmux and eager transport handshakes. Handle `appinit.Metrics` initialization errors and close its returned resource. Sinks still initialize once per process.

- B10: `restserver/authz` now denies an authenticated role with 403 `forbidden` (`codes.PermissionDenied`); an empty or `guest` role still receives 401 `unauthorized`, now `codes.Unauthenticated` over gRPC. The denial message is `<role> role not allowed` without the previous `request <id>: unauthorized:` prefix; the request ID stays in `request_id`. `httperror` maps `codes.PermissionDenied` to 403 (was 401) and `CodeUnauthorized` to `codes.Unauthenticated` (was `PermissionDenied`), so 401 and 403 round-trip through gRPC. Clients matching 401 for denied-but-authenticated calls, or `PermissionDenied` for `httperror.Unauthorized`, must match 403 / `Unauthenticated` instead. REST `OPTIONS` requests other than CORS-answered preflights now need authorization; with `OptionsPassthrough`, application OPTIONS handlers on restricted paths need a permitted role. Custom `WithMuxFactory` chains must place CORS outside authz themselves.

- `httperror.CodeRequestTooLarge` now maps to gRPC `ResourceExhausted` (was `InvalidArgument`), matching grpc-go's oversized-message code. `Error.GRPCStatus` and `ManyError.GRPCStatus` attach an `@httperror.code` status detail beside `@correlation.id`, and `NewFromPb`, `Wrap` and `Status` use it to restore HTTP 413 `request_too_large`; a bare `ResourceExhausted` still converts to 429. gRPC clients that matched `InvalidArgument` for oversized requests must match `ResourceExhausted`. An `Error` whose code has no gRPC mapping now returns a status with code OK instead of nil when it carries a request ID.

- `KeypairReloader` now returns an error for an expired certificate at initial load or reload, and `Reload` returns an error after `Close`. Its TLS callbacks return an error if the current certificate expires; `Keypair` returns nil. `TLSInfo.ServerTLSWithReloader` also routes handshakes without SNI through that callback, so its returned config no longer exposes a static `Certificates` entry. Rotate certificates before expiry and handle reload and handshake errors. TLS constructors also reject CA files with no valid certificate. `NewHTTPTransportWithReloader` now clones a supplied transport; callers should use the returned `HTTPTransport` for requests and close it when done.

- `restserver.StopHTTP` now drains active requests before calling `Service.Close`. Services that must stop accepting work earlier can use a `ServerStoppingEvent` handler. After the shutdown timeout, services still close even if handlers have not finished.

- B07: `gserver.Start` now rejects an enabled `rate_limit` block whose `requests_per_second` is not positive (previously one request per client was admitted and every later one got 429), whose `expiration_ttl` is negative or shorter than one second (an expired bucket is recreated with a full burst), whose `headers_ip_lookups` contains a name other than `RemoteAddr`, `X-Forwarded-For` or `X-Real-IP` spelled exactly, or whose `metods` contains an entry that is not a single upper-case HTTP method token, such as `get`, `"GET "` or `GET,POST` (tollbooth ignored other names and methods and limited nothing). `Config.Validate` and the new `RateLimit.Validate` report the same errors.

- `rpcclient.New` now rejects a TLS configuration paired with `http://`, `unix://`, or a bare endpoint. Change the endpoint to `https://` or `unixs://` to keep TLS and per-RPC credentials enabled.

- `Scheduler.List` now returns a copy of its slice, `Task.Schedule` returns a snapshot, and `New(s)` copies its input schedule. Use `Add`/`Clear` and `SetNextRun`/`UpdateSchedule` to change live state; mutating returned values or the original `s` no longer changes the scheduler or task.

- B11: cache subscribers must expect message gaps under load instead of a blocked publisher, and check `ReceiveMessage` errors: `cache.ErrClosed` after `Close`, the context error when it is done, and a subscribe failure for a Redis subscription that could not be established (re-subscribe to recover). A Redis `ReceiveMessage` no longer returns connection errors: go-redis reconnects and resubscribes in the background and messages published meanwhile are lost; closing a memory or Redis provider closes its subscriptions, whose `ReceiveMessage` then returns `cache.ErrClosed`; a `Subscribe` during or after the provider's `Close` returns a failed subscription reporting `cache.ErrClosed` on both providers (a memory provider previously kept accepting subscriptions after `Close`), and `Subscription.Close` may wait for an in-flight redial during an outage. `Close` discards buffered messages on both providers and releases a go-redis reader blocked on a full buffer at once. Memory `Publish` with an already-done context now returns its error.

- `cache.GetOrSet` now writes on a cache miss. Callers that require a read without a cache write should use `Get` and their getter directly. On a miss, the destination must point to a concrete type; interface destinations return an error because their values cannot round-trip reliably across providers.
