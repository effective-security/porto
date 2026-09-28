# porto v0.41 release notes

## Major fixes

### Security

- gRPC-Web CORS now requires an enabled `cors` block and an explicit allowed origin. For both REST and gRPC-Web, an enabled CORS block with an empty origin list now allows none; set `allowed_origins: ["*"]` to retain the old wildcard behavior (and `enabled: true` if enabling gRPC-Web CORS). `Start` now returns an error when an enabled `cors` block combines `allowed_origins: ["*"]` with `allow_credentials: true`; credentialed CORS needs explicit origins or origin patterns. While `cors` is enabled, `Start` also rejects `Access-Control-*` names in `http_headers`; move those settings into the `cors` block. Disallowed gRPC-Web POSTs receive HTTP 403; disallowed preflights receive no allow-origin header. REST requests from disallowed origins still reach their handlers without CORS headers, so REST CORS is not CSRF protection. Configured exposed headers are preserved without duplicate names.

- Redact credential headers from retriable HTTP client debug dumps. Token and DPoP key writes now use private temporary files and replace existing credential paths atomically; newly created credential folders use mode `0700`.

### Concurrency, deadlocks and panics

- TLS certificate reloads now load files outside the handshake lock. The reloading HTTP transport keeps one TLS config and selects the current client certificate for each handshake; it clones a supplied `http.Transport` and closes idle connections after rotation and on `Close`.

- Synchronize retriable client setters and token refresh; missing or public-only DPoP signing keys now return errors.

- Make discovery registration and lookup safe for concurrent use; nil services now return an error, and iteration callbacks may register services.

- Synchronize scheduler and task state, and make repeated `Stop` calls safe. A stopped scheduler can be restarted.

### Correctness and interoperability

- Return REST server HTTP bind errors from `StartHTTP`, support `Config()` and IPv6 bind addresses (`HostName()` returns IPv6 hosts without brackets; `GetServerURL` and `GetServerBaseURL` add them), and make `StopHTTP` safe before start and on repeated calls.

- Route `unix:///path` and `unixs:///path` gRPC client endpoints through the Unix socket resolver without appending a TCP port.

- Sign a fresh DPoP proof for each retry attempt.

- Forward a normalized correlation ID from HTTP requests to gRPC metadata, including the `x-request-id` alias when present.

- Honor gzip quality values for JSON responses, skip compression below 1 KiB, and add `Vary: Accept-Encoding`. Compressed JSON and unary gRPC-Web responses now reuse gzip writers.

- `cache.GetOrSet` now stores a successful getter result using the provider's default TTL, reports invalid getter types without panicking, and returns cache write errors.

### Tests and tooling

## New features and behaviour

- B06: shared `xhttp/limits` defaults bound HTTP header reads (10s), whole-request reads (30s), idle keepalive connections (60s), cmux detection and eager TLS handshakes (10s). Header deadlines follow native net/http semantics; HTTP/2 has no per-stream header deadline. Request bodies default to 10 MiB, including standalone `marshal.DecodeBody`. Unknown-length bodies and trailing bytes are bounded too; `RequestTooLarge` now returns HTTP 413.
- Prometheus binds synchronously, returns bind errors without terminating the process, and returns a closer that shuts down its HTTP endpoint. Its endpoint also uses the shared read/body limits.

## Breaking changes: what clients must change

- B06: raise or disable read/body limits for large uploads and long request streams using `gserver.Config.Timeouts`/`MaxRequestBody`, REST `WithTimeouts`/`WithMaxRequestBody`, or Prometheus `timeouts`/`max_request_body`. Zero selects defaults and negative values disable individual limits. `restserver.MaxRequestSize` is now enforced and is 10 MiB (previously an advisory 64 MiB). Native plaintext gRPC retains per-message limits; TLS gRPC/gRPC-Web request streams receive HTTP body limits. Native net/http TLS handshakes use the smaller positive header/read deadline; `Handshake` configures cmux and eager transport handshakes. Handle `appinit.Metrics` initialization errors and close its returned resource. Sinks still initialize once per process.

- `KeypairReloader` now returns an error for an expired certificate at initial load or reload, and `Reload` returns an error after `Close`. Its TLS callbacks return an error if the current certificate expires; `Keypair` returns nil. `TLSInfo.ServerTLSWithReloader` also routes handshakes without SNI through that callback, so its returned config no longer exposes a static `Certificates` entry. Rotate certificates before expiry and handle reload and handshake errors. TLS constructors also reject CA files with no valid certificate. `NewHTTPTransportWithReloader` now clones a supplied transport; callers should use the returned `HTTPTransport` for requests and close it when done.

- `restserver.StopHTTP` now drains active requests before calling `Service.Close`. Services that must stop accepting work earlier can use a `ServerStoppingEvent` handler. After the shutdown timeout, services still close even if handlers have not finished.

- `rpcclient.New` now rejects a TLS configuration paired with `http://`, `unix://`, or a bare endpoint. Change the endpoint to `https://` or `unixs://` to keep TLS and per-RPC credentials enabled.

- `Scheduler.List` now returns a copy of its slice, `Task.Schedule` returns a snapshot, and `New(s)` copies its input schedule. Use `Add`/`Clear` and `SetNextRun`/`UpdateSchedule` to change live state; mutating returned values or the original `s` no longer changes the scheduler or task.

- `cache.GetOrSet` now writes on a cache miss. Callers that require a read without a cache write should use `Get` and their getter directly. On a miss, the destination must point to a concrete type; interface destinations return an error because their values cannot round-trip reliably across providers.
