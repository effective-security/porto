# Findings remediation plan

This queue groups the open issues in [FINDINGS.md](FINDINGS.md) into
reviewable implementation batches. P-001 is already marked Fixed and is not
queued. The batches follow package ownership and shared behavior; a finding
that spans packages is completed only when every named part is fixed.

Work from top to bottom within each priority. Independent batches can proceed
separately. A batch with an entry in the **Decision** column needs its compatibility or
configuration choice resolved before changing the affected behavior. Its
reproduction, tests, and design can proceed while that choice is pending.
The related larger designs are recorded in [ROADMAP.md](ROADMAP.md).

## Completed B06 decision — network limits

Zero selects shared defaults: HTTP headers 10s, whole-request reads 30s,
idle connections 60s, cmux detection and eager TLS handshakes 10s, and
HTTP request bodies 10 MiB. Positive values override; negative values disable
individual limits. `gserver.Config.Timeouts` is separate from the existing
shutdown-only `Timeout.Request`. REST exposes fluent options without changing
its Config interface. Native net/http TLS handshakes use the smaller positive
header/read deadline. No response write deadline is introduced. Header uses
native net/http semantics; HTTP/2 has no per-stream header deadline.

Body limits apply to HTTP handlers, including custom REST muxes, and to
standalone `marshal.DecodeBody`; native gRPC keeps its per-message limits.
On TLS listeners, HTTP body limits also apply to gRPC/gRPC-Web request streams;
native gRPC streams there are exempt from the read deadline but keep the body
limit as a per-stream total (ROADMAP 12). The body limiter writes no response:
a known oversized body fails on its first read before any byte is read.
`DecodeBody` returns HTTP 413 for it and for any other oversized JSON body,
from inside the CORS, correlation and telemetry middleware.
`request_too_large` maps to gRPC `ResourceExhausted` and converts back to 413
through its code detail.
Prometheus binds synchronously and returns bind errors; its returned closer
closes the HTTP server. Unexpected serve errors are logged, never fatal.
Deployments with large uploads or long request streams must raise or disable
the relevant read/body limits; metrics callers must handle initialization
errors and close the returned resource.

## Completed B10 decision — HTTP errors and authorization

`httperror` follows the Google API mapping for authentication and
authorization: `codes.Unauthenticated` ↔ HTTP 401 `unauthorized` and
`codes.PermissionDenied` ↔ HTTP 403 `forbidden`, so both statuses round-trip
through gRPC (`CodeUnauthorized` now maps to `Unauthenticated`, previously
`PermissionDenied`, and `PermissionDenied` now converts to 403, previously
401). `restserver/authz` denies an empty or `guest` role with 401
`unauthorized` (`Unauthenticated`) and any other role with 403 `forbidden`
(`PermissionDenied`); the message is `<role> role not allowed` (an empty
role is reported as `guest`) without a second wrapping, and the request ID
is the `request_id` field. authz never skips `OPTIONS`: the preflight
headers are caller-controlled, so CORS preflights are answered by the CORS
middleware placed outside authz (`restserver.NewMux` now wraps authz with
CORS instead of the router; `gserver` already did), and with
`OptionsPassthrough` an `OPTIONS` request is authorized like any method.
Denied and not-ready REST responses now carry CORS headers.
`Error.WriteHTTPResponse` and `ManyError.WriteHTTPResponse` never
modify the error they write: a missing `request_id` is filled in a
per-request copy, so `Error` values may be shared (`ManyError` snapshots
its nested errors under its lock and writes after releasing it), and
`restserver/ready` builds its 503 per request. `marshal.WriteJSON` sends converted non-`httperror`
errors that map to 5xx with the generic `http.StatusText` message and logs
the original as the cause; 4xx conversions and explicit `httperror` values
keep their text. Identity mapper failures are logged and answered with a
generic `invalid identity` 401 (`Unauthenticated` over gRPC) unless the
mapper's error wraps a non-nil `*httperror.Error` with an HTTP status,
which is returned unmodified.
`errMsg` no longer panics on a non-string format value. Clients that
matched 401 for authenticated-but-denied requests, `PermissionDenied` for
`httperror.Unauthorized`, or relied on the previous 5xx or identity error
text must adjust; REST `OPTIONS` requests other than preflights answered by
CORS now need authorization, and custom mux factories must keep CORS outside
authz.

## Completed B03 decision — gRPC-Web CORS

An absent or disabled `cors` block emits no gRPC-Web CORS headers and does not
reject requests solely because they carry `Origin`. With CORS enabled, an
explicit `*` allows any origin; a nonempty list uses `rs/cors` matching,
including configured origin patterns; an empty list allows none. `Start`
rejects `*` combined with `allow_credentials`, so credentialed CORS always
names its origins, and rejects `Access-Control-*` names in `http_headers`
while CORS is enabled. REST and preflight CORS retain their configured pattern
matching. A disallowed gRPC-Web POST receives HTTP 403 without gRPC-Web
framing; preflights for disallowed origins receive no allow-origin header.
Configured exposed headers are merged with the automatic gRPC-Web header list
without case-insensitive duplicates. Deployments that relied on the previous
implicit wildcard must explicitly enable CORS and configure
`allowed_origins: ["*"]`.

## Completed B02 decision — TLS reloader and client transport

The reloader rejects an expired certificate at initial load and on reload;
on reload failure it keeps the previous pair. Once that pair expires, TLS
callbacks return an error and `Keypair` returns nil. The HTTP wrapper clones
a supplied `http.Transport`, installs a stable TLS config with a live client
certificate callback, and closes idle connections after rotation. Invalid CA
files return errors. Callers must rotate certificates before expiry, handle
reload and handshake errors, use the returned HTTP wrapper for requests, and
close it when done. The server wrapper clears static certificates so clients
without SNI also use the callback; the HTTP wrapper closes idle connections
on `Close`.

## Completed B07 decision — gserver lifecycle and rate limits

An enabled `rate_limit` block is validated by `Start` through
`Config.Validate` instead of receiving a default: `requests_per_second` must
be positive; `expiration_ttl` must not be negative and, when set, must be at
least one second (tollbooth recreates an expired bucket with a full burst, so
a shorter TTL grants a burst that often); every `headers_ip_lookups` entry
must be one of the names tollbooth understands (`RemoteAddr`,
`X-Forwarded-For`, `X-Real-IP`, spelled exactly); and every `metods` entry
must be a single upper-case HTTP method token (RFC 9110 tchar characters,
so `"GET "` or `"GET,POST"` are rejected too), because tollbooth compares
both exactly and a non-matching entry limits nothing. A disabled or absent block is not
validated. No default rate is applied: the previous behavior (one request
per client, then 429) was never a working configuration, and a silent
default would pick an arbitrary limit. Deployments that set `enabled: true`
without a rate, with a negative or sub-second TTL, with a misspelled lookup
name or with a method entry that is not an upper-case token now fail at
startup and must fix the block.

`Start` releases everything it acquired when it fails (created services,
listeners and the TLS reloader) on every error path: a failed or missing
service factory now closes the services created before it, and the cleanup
no longer depends on a shadowed error variable. `configureListeners` now
really closes the listeners it opened before a later listen URL failed (its
deferred cleanup previously read a named result that the error return had
already reset to nil, so the first listener stayed bound) and stops the
reloader it started. `serve` starts no
server until every fallible step succeeded and always closes its server
channel, so `Close` returns after a failed listener setup instead of
blocking. `Close` stops the TLS certificate reloader after closing the
listeners, and its teardown runs once under `closeOnce`: services are closed
once, and a repeated or concurrent `Close` returns after the first teardown
has finished (previously a second call closed the services again).

## Completed B05 decision — trusted proxy headers

Forwarding headers are ignored unless the socket peer belongs to an explicitly
configured trusted proxy CIDR. `gserver` uses `trusted_proxy_cidrs` and
`restserver.HTTPServer` uses `WithTrustedProxies` with a policy from
`identity.ParseTrustedProxies`; neither trusts proxies by default. A trusted peer's XFF chain is read from right to left, stopping at
the first untrusted address, including private addresses, or the leftmost
entry when every hop is trusted. Invalid values
fall back to the socket peer. `X-Real-Ip` applies only without XFF.
`X-Forwarded-Proto` must be exactly `http` or `https`. Proxies configured here
must overwrite forwarding headers received from clients. The client IP is
resolved once per request at the trust boundary. A request without a socket
peer (served in process) has no client IP and resolves to "" instead of the
server's local IP. The default rate limiter keys on this resolved IP and
echoes it, not the socket peer, in `X-Rate-Limit-Request-Remote-Addr`;
requests without a client IP are not limited. Deployments with explicit
`headers_ip_lookups` retain that override and must ensure those fields are
set by a trusted proxy.

## Completed B11 decision — cache pub/sub slow-subscriber policy

Pub/sub delivery is at most once and `Publish` never waits for a
subscriber. Each subscription buffers 100 undelivered messages. The memory
provider drops the message for a subscriber whose buffer is full and
returns nil; it returns `ctx.Err()` only when ctx is already done. Redis
subscriptions read through go-redis `PubSub.Channel` (one reader and one
health-check goroutine per subscription, automatic reconnect and
resubscribe); its reader waits up to one minute for a full channel, then
drops the message, so a Redis subscriber that stops draining stalls its own
connection first and loses messages later. `ReceiveMessage` starts no
goroutine and returns promptly with `ctx.Err()` when ctx is done or
`cache.ErrClosed` after `Close`; `Close` is idempotent and unblocks a
pending receive. Redis `Subscribe` waits for the server's subscription
confirmation (bounded by ctx; without it, by the go-redis dial timeout for
connecting plus 10s for the confirmation) so a message published after
`Subscribe` returns reaches the subscriber, matching the memory provider;
a subscription that could not be established is returned as a
`Subscription` whose `ReceiveMessage` returns the wrapped error and whose
`Close` is a no-op, because the `Subscribe` signature has no error result.
A Redis subscription does not report connection loss: go-redis reconnects
and resubscribes in the background and messages published meanwhile are
lost; closing a provider (memory or Redis) closes its live subscriptions
first, so `ReceiveMessage` returns `ErrClosed`, queued messages are
discarded and the go-redis goroutines are released; registration is
serialized with `Close` on both providers, and a `Subscribe` after or
during `Close` returns a failed subscription reporting `ErrClosed`; `Close` on a subscription drains the
go-redis channel so a reader blocked on a full buffer exits at once instead
of after its one-minute send timeout, and may wait for an in-flight redial
during an outage. Buffered messages are discarded by `Close` on both
providers. Subscribers must treat a message gap as possible and
re-subscribe after a failed `Subscribe`; `Publish` errors now carry the
channel name.

## Completed B12 and B13 decision — Redis coordination, secrets and key namespaces

B13 was done with B12: both change `pkg/redisclient` key handling, and the
cache part shares the Redis fixture and the key helpers.

Lock: `TryLock` returns a random owner token (`crypto/rand.Text`) instead of
a bool; an empty token means another owner holds the lock for the returned
remaining time (`PTTL`, read in the same MULTI/EXEC as `SET NX PX`).
`ReleaseLock(ctx, key, token)` deletes the lock only while it holds the
token (Lua compare-and-delete) and returns false for an expired or foreign
lock; an empty token is an error. The signature change is deliberate:
callers of the old `ReleaseLock(ctx, key)` fail to compile instead of
silently releasing other owners' locks. Locks written by earlier versions
hold a timestamp and cannot be released by a token: they expire, except
those taken with a zero timeout, which never expire and need a manual
`DEL <prefix>lock:<key>`. Timeouts below 1ms are errors. Under a prefix, a
lock or rate-limit key whose `..` segments would leave its
`lock:`/`ratelimit:` sub-namespace (`x/../../data`, `a/../b`) is rejected
with an error (previously it named a data key); without a prefix keys are
not cleaned and are used as is.

Rate limiter: the one-execution-per-window contract and the
`ratelimit:<key>` key stay, but the key is now a string written with
`SET NX PX`: one call per window wins, denied calls write nothing, the
check and the write are one command, and the window runs on the server
clock. The allowed call's window applies until it expires.
`GetRateLimitRemainingTime` is the key's `PTTL` (0 when none);
`ratelimit_window:<key>` is no longer written. The key name is kept so that
mixed versions fail closed during a rolling upgrade: a sorted set left by an
earlier version denies new callers until it expires, and an earlier
version's call returns a `WRONGTYPE` error while a new window is active;
its pipelined `EXPIRE` still resets the window to its own length, so while
earlier versions keep polling, no caller is allowed. Finish the upgrade
(or stop the earlier callers) to resume. Windows below 1ms are errors.

Eviction helpers run one Lua script each. A member or field is appended to
the order list only when it is new, after removing stale entries for it
(left by `SRem`/`HDel`, an expired collection or an earlier version), so
re-adds and updates keep their position (FIFO by first insertion, as
documented) and a stale entry cannot evict a re-added member; eviction
repeats until the list is within the limit; a wrong-type key fails before
any write, and errors are returned wrapped. The limit must be positive and
the two keys must differ. A duplicate written by an earlier version for a
member that is still in the set can evict it once until it ages out. The server must
allow Lua scripting.

Close: the root `Close` returns the close error, is idempotent and keeps the
embedded client, so later commands on the root and its `WithPrefix`
children fail with `redis.ErrClosed` instead of panicking; children still
share the connection. Secrets: `NewRedisClient` logs only the address and
DB, and `redisclient` and `cache.NewRedisProvider` drop the URL from
`url.Parse` errors.

Key namespaces: keys are neither rejected nor concatenated uncleaned. A key
is cleaned as a rooted path before it is joined with the prefix
(`path.Join(prefix, path.Clean("/"+key))`), so `..` cannot climb above the
prefix while every key whose `..` segments stay below the key's own first
segment keeps its stored name, including keys with leading, trailing or
doubled slashes; a key whose `..` climbed above it (such as `../x`, or
`../app/x` under `/app/`) now resolves inside the prefix. `Key` keeps its signature;
`WithPrefix` and `NewProxyProvider` clean their prefixes (a proxy prefix
cannot leave its parent's namespace). `Keys` (all cache providers,
`redisclient.Keys`/`ScanKeys`) takes a Redis glob relative to the provider,
cleaned like a key, escapes glob metacharacters in the prefix and returns
relative keys without a leading slash that round-trip through `Get`:
cache providers skip names that no key maps to and list the key `""` only
for an empty pattern. The memory provider ports the Redis matcher (`*` and
`?` match `/`; ranges compare unsigned bytes, so ranges mixing bytes
>= 0x80 with ASCII can differ from Redis builds with signed `char`), skips
expired entries and returns an empty, non-nil slice. Callers that parsed
prefixed names from memory or proxy `Keys`, or the leading `/` from Redis
`Keys` under a prefix without a trailing slash, must use the relative keys;
data written through escaping `..` keys is no longer reachable by them.

## Completed B15 decision — TLS listener and policy

The six `transport.TLSInfo` fields that were never enforced (`AllowedCN`,
`AllowedHostname`, `EmptyCN`, `ServerName`, `InsecureSkipVerify`,
`SkipClientSANVerify`) are removed rather than implemented: `ServerName`,
`InsecureSkipVerify` and `EmptyCN` describe a client's own config in etcd,
where they came from, and its SAN check did a reverse DNS lookup per
connection. Nothing in this module or the sibling modules set them. A
caller that did now fails to compile instead of assuming a check that never
ran; other client-certificate policy is set with `VerifyConnection` on the
config returned by `ServerTLSWithReloader` before `NewTLSListener` serves.
This retires ROADMAP 8.

`ServerTLSWithReloader` caches its config and reloader only after every
step succeeded, so a failed call (expired certificate, bad cipher list,
reloader error) leaves nothing behind and a retry loads the files again.
`NewTLSListener` still closes `l` only for a nil or empty `TLSInfo`; when
`ServerTLSWithReloader` fails, `l` stays open and belongs to the caller
(now documented, so a retry can reuse it).

Accept errors are returned unwrapped by both listener types, so net/http,
grpc and cmux can type-assert `net.Error` and retry temporary errors such
as `EMFILE`. The TLS listener no longer stops its accept loop on the first
error: it hands each error of the wrapped listener to one `Accept` call and
keeps accepting, and stops only when the wrapped listener returns
`net.ErrClosed` or `Close` is called; `Accept` then returns an error
wrapping `net.ErrClosed` (the caller, not the listener, decides whether an
error is temporary, and the loop waits for each `Accept` call, so the
caller's backoff paces it). A wrapped listener that reports its closure
with another error (cmux) keeps the loop running until `Close`; net/http
and grpc close their listener when such an error stops them. The caller
recovers from an error storm up to one of its backoff periods later than
on a raw listener, because the loop holds the next error until the next
`Accept`; tracking waiting callers to avoid that was judged not worth the
complexity. Previously one `EMFILE` made the gserver cmux loop and every
TLS listener stop serving for good.

cmux retries temporary errors at once, so unwrapped errors alone would make
gserver spin on one core per address during descriptor exhaustion
(recorded during the batch as P-082, B26; fixed here). `gserver` wraps every
root listener (TCP and Unix) in `backoffListener`, which waits 5ms doubling
to 1s after each failed `Accept` (the net/http schedule, reset by a
successful accept, cut short by `Close`) and logs each failure as a
warning; the error itself is returned unchanged, so cmux still stops on
non-temporary errors, and `net.ErrClosed` is returned without waiting.

Keepalive listeners use `SetKeepAliveConfig` with idle 30s, interval 15s
and 9 probes. These are the values Go 1.27 produced before (its accept
default of 15s/15s/9 with the idle time raised to 30s), now set explicitly
so they no longer depend on how the wrapped listener was created.
Connections without keepalive support (non-TCP) are returned unchanged
instead of panicking, and a failure to set the options is logged at DEBUG
and does not fail `Accept`. The `pkg/tlsconfig` part of P-074 stays in B23.

## Completed B16 decision — HTTP client retries and transport

`RequestPolicy` values replace the `DefaultPolicy` values only when
non-zero (`cmp.Or`), so a `request:` block with only `timeout` keeps the 5
retries; a negative `retry_limit` disables retries (the zero/negative
convention of B06). Configs that wrote `retry_limit: 0` to disable retries
must write `-1`.

`ShouldRetry` delegates 429 to `Retries[429]` like a 5xx status; without an
entry it still stops with `LimitExceeded`. `DefaultPolicy` registers the new
`RetryAfterShouldRetryFactory(2, 1s, 30s, "rate-limit")`: up to 3 retries,
each after the response's `Retry-After` (delay-seconds or an HTTP date; a
past date means no wait; an overflowing value saturates), or 1s without a
valid one. A `Retry-After` above 30s stops at once with `LimitExceeded`, so
callers are not held for minutes. The factory is exported for custom
policies (for example 503). The `gserver` rate limiter (tollbooth) sends no
`Retry-After`, so a default client now retries its 429 after 1s, when the
limiter usually admits it; `gserver` `TestRateLimit`, which checks the
limiter's 429, now uses a policy without the 429 entry. `DefaultShouldRetryFactory(limit, ...)` keeps
its `retries <= limit` semantics (limit+1 retries); the docs that called the
default connection entry "3x" now say 4.

`Do` waits between attempts on a timer and `ctx.Done()`: a cancelled or
expired context ends the wait with an error wrapping the context error
(`<METHOD> <URL>: waiting to retry: ...`, password redacted); while the
context is live, a retry whose wait would pass its deadline is not
attempted, and the last response is returned unread (once the deadline has
passed, the body could not be read, so the context error is returned). Retried bodies are drained up to 64 KiB and
closed; retry warnings redact URL passwords. `executeRequest` releases the
`RequestTimeout` context when the returned body is closed (as `Request` and
`HeadTo` do), or at once on error.

The nonce cache drops its oldest half when full (previously it dropped the
newest cached nonce). `NonceProvider` gains `NonceContext(ctx)`; `Nonce()`,
the `jose.NonceSource` method, fetches with a 30s timeout. External
`NonceProvider` implementations must add the method (there are none in the
sibling modules).

`WithTLS` and `WithDNSServer` install a modified clone of the current
`*http.Transport` and never change a supplied one, including
`http.DefaultTransport` (the DNS tests passed it and rewired DNS for the
whole test process). On any other `http.RoundTripper`, or when
`http.DefaultTransport` itself is not an `*http.Transport`, they fail
closed: `New` returns the error, and after `New` every request returns it
until `WithTransport` replaces the transport. `Do` copies the `*http.Client`
under the client lock, so transport setters are safe while requests are in
flight. A clone holds a copy of the TLS config (`tls.Config.Clone`), so a
`*tls.Config` passed to `WithTLS` is copied by a later `WithTLS` or
`WithDNSServer` call, and changes to it after that call are not seen. When
a transport the client created is replaced (by `WithTLS`, `WithDNSServer`
or `WithTransport`), its idle connections are closed; a transport passed to
`WithTransport` is never closed. `Do` closes the request body when it
returns the recorded error. The review found that a `WithTransport` option
also drops `ClientConfig.TLS` without an error; that predates B16 and is
recorded as P-083 (B27).

`RequestURL` builds the request from the parsed URL (`RequestURI()` plus the
fragment, and the host re-escaped so IPv6 zones work) instead of byte
offsets into the raw string, and rejects URLs without a scheme, opaque URLs
(`https:host/path`) and URLs with user info: user info never worked (the
path was sliced at the wrong offset) and would put credentials into logged
URLs.

`NewStorage` expands `~` with `os.UserHomeDir`, falling back to
`user.Current().HomeDir` when `HOME` is unset (go-homedir also had a
fallback); go-homedir is now only an indirect dependency (through
`x/fileutil/resolve`). `NewStorage` still does not expand `~user` or
`$VAR`, and keeps the literal folder when no home directory is known. `WithUserAgent` no longer waits up to 1s for a network interface and
omits `X-CLIENT-HOSTNAME`/`X-CLIENT-IP` when they cannot be resolved
(previously sent empty). `DecodeResponse` reads at most 64 KiB of an error
body (the error text is truncated there) and returns a read error instead
of the partial text; DEBUG dumps log the headers and that bounded body.

## Completed B17 decision — HTTP telemetry labels and response writer

Request metrics use bounded labels only (P-023). `uri` is the route
template recorded with the new `telemetry.SetRoute(ctx, pattern)`: the
`restserver` Router records the registered path of the route it dispatches
to (for example `/v1/users/:id`, `/v1/files/*path`), so both `restserver`
and `gserver` REST routes are labelled by template. Requests without a
recorded route are labelled `unknown` (`telemetry.UnknownRoute`): unmatched
paths and responses produced before or instead of a route handler, which
includes authz 401/403 denials, readiness 503, `restserver` CORS
preflights, httprouter's own 405, automatic `OPTIONS` and trailing-slash
redirects, and `gserver` `WithMiddleware` handlers that answer requests
themselves.
`verb` keeps the 9 standard net/http methods and maps any other method to
`_OTHER` (`telemetry.OtherMethod`, the OpenTelemetry convention). The 404
special case is gone: every request records both `http_requests_perf` and
`http_requests_role`, so a 404 from a matched route keeps its template and
an unrouted 404 now also records a latency sample under `unknown`.
`NewRequestMetrics` places the route holder in the request context (reusing
an enclosing one); it is atomic because `http.TimeoutHandler` can leave the
handler running after the metrics are recorded. Custom mux factories that
add `NewRequestMetrics` get templates for `restserver.NewRouter` routes and
`unknown` for other handlers unless those call `SetRoute` with the
registered pattern. Dashboards and alerts that select raw paths, or
401/403 by path, must move to templates or `unknown`.

`ResponseCapture` implements `Unwrap` (P-024), so `http.ResponseController`
deadlines, full duplex, flush and hijack reach the connection through the
two captures in every chain, and implements `http.Hijacker` directly for
WebSocket libraries that assert it; `Flush` and `Hijack` go through
`http.ResponseController`, so a missing feature is a no-op flush or an
error wrapping `http.ErrNotSupported`; the new `FlushError`, which
`http.ResponseController.Flush` calls, returns the flush error that
`Flush` must drop (previously it returned nil through the capture). Captured status
and size exclude bytes written to a hijacked connection. `NewRequestLogger`
clamps a granularity below 1ns to 1ns (P-031) instead of dividing by zero.

The review found that responses produced outside the metrics handler
(identity mapper 401s, `gserver` rate-limit 429s and CORS preflights) were
never counted, and that `ResponseCapture` hides `io.ReaderFrom`; both
predate B17 and are recorded as P-084 and P-085 (B28). `Test_Authz` now
asserts the exact metrics of each request (two subtests passed on
counters left by earlier ones).

## Completed B19 decision — caller credentials and cookie CSRF

Cookie authentication requires the CSRF check on every path (P-013).
`roles.New` returns `cookies: csrf is required when auth is set` when JWT is
enabled with `cookies.auth` but no `cookies.csrf`; HTTP previously ignored
the auth cookie then without notice. With JWT disabled the cookie settings
are unused and still accepted. gRPC and gRPC-Web calls authenticated by the
auth cookie need `x-csrf-token` metadata (the `X-CSRF-Token` header for
gRPC-Web, now `header.XCSRFToken`) equal to the CSRF cookie in the `cookie`
metadata; every RPC is a POST, so the check is never skipped. A failed
check falls through to the TLS certificate or guest and never returns an
error, even in `Strict`, as on HTTP. Both paths share `checkCSRF`, which
ignores surrounding spaces on both values and whose errors no longer
contain either value (P-009). With `debug_logs`, the gRPC metadata dump now
redacts `authorization`, `proxy-authorization`, `cookie`, `dpop` and
`x-csrf-token` values, which it logged in full.

STS failures caused by the presigned URL are cached (P-010): 4xx except
408, 429 and the throttling codes `Throttling`, `ThrottlingException` and
`RequestLimitExceeded` (STS throttles with HTTP 400, so the approved "4xx
except 429" alone would have cached throttling; the code is read from the
JSON or XML error body), and an undecodable 200 body. They are kept for 30s
in a separate 100-entry LRU, so bad tokens cannot evict successful lookups,
and return `cached STS lookup failure: <error>`. `InvalidClientTokenId` is
cached, so a token signed with an access key that IAM has not yet
propagated is rejected for up to 30s. Transport errors, timeouts, 408, 429,
throttling and 5xx are not cached. Concurrent lookups of one uncached URL
share one STS call made with the context of the request that started it,
so a reset request still cancels its call and no lookup outlives its
request. This replaces the first approved design, a detached lookup under
`context.WithoutCancel`, after the review showed that clients resetting
streams could then keep unbounded STS calls running; the user confirmed
the change. Clients with deadlines shorter than STS latency still never
fill the cache, as before. A waiter returns its own context error if that
ends first, and a live waiter makes the next call when the shared one
failed after its request's context ended. A panicking lookup releases its
waiters with an error and the panic continues on its request. The review
found that transport and URL parse errors (`*url.Error`) carried the full
presigned URL, a bearer credential, into errors and logs; only their cause
is kept now, with the host.

`perRPCCredential` reads the token, DPoP signer and provider under one lock
(P-014) and refreshes an expired token with one `GetCallerIdentity` call
shared by concurrent RPCs, made with the context of the RPC that started it.
A waiter whose context ends first returns its context error; a live waiter
makes the next call when the shared one failed after its RPC's context
ended, or when `WithCallerIdentity` replaced the provider meanwhile (the
running call's result is then discarded, also for its own RPC). Unlike
`pkg/retriable`, which retries on any context-typed error, only the end of
the calling RPC's context triggers the retry. Waiters take the shared
call's token even when it expires within a minute. The signer is read after
the refresh, as before, so a provider that installs the signer bound to the
new token with `WithDPoP` gets proofs from that key on the refreshing RPC
and on the RPCs that shared its result. A panicking provider
releases the waiters with an error and the panic continues. Provider errors
are wrapped (`unable to get caller identity: ...`), a nil token is an error
instead of a panic, and the stored token, including one set with
`UpdateAuthToken`, is a copy. `bundle.NewWithMode` returns an error (P-015):
the grpclb and RLS balancers call it, and a copy that ignored the mode
would send the bundle's token to the balancer. grpclb logs the error and
dials its balancer with the same fallback credentials as with the nil
bundle; RLS now fails with this error instead of the missing transport
security error of `grpc.NewClient`. Porto itself does not call it.

The review found that each `roles.New` leaks the cleanup goroutine of the
successful-lookup cache (P-086, B29) and that `pkg/retriable` `callerToken`
has the provider-panic gap fixed here (P-087, B30).

Migration: set `cookies.csrf` wherever `cookies.auth` is set with JWT.
gRPC and gRPC-Web clients that authenticate with the auth cookie must send
the CSRF cookie and `X-CSRF-Token` (`x-csrf-token` metadata) with its value;
cross-origin browser clients also add it to `cors.allowed_headers`.

## Completed B21 and B23 decision — app initialization and TLS cipher names

B21 (P-067, P-068 and P-073, plus P-088 and P-089 found by the reviews). The
`appinit.Metrics` closer cancels the context of `cloudwatch.Sink.Run` and
waits for it to return, so the publishing goroutine stops after `Run`
published the last interval (the sink bounds that publish by 10s and logs
its error). An interval is lost when the cancellation aborts a periodic
publish in flight or meets a tick `Run` has not handled yet, and `Close`
publishes nothing when `Run` already stopped on expired or missing
credentials; fixing those needs a change to `cloudwatch.Sink.Run` in the
metrics module. P-088: with `runtime_metrics`, the runtime stats collector
of the global `*metrics.Metrics` also ran for the life of the process; the
closer now signals it to stop (without waiting) before the CloudWatch
runner. `CPUProfiler` returns the
`pprof.StartCPUProfile` error; a second call while its own profile runs
fails before creating (truncating) the file, and a failed start closes and
removes the file, clearing the flag only after the removal (P-089, found
by the review and the PR 603 review: releasing it first let a concurrent
call start a profile on the same path that the removal then unlinked); the
closer stops the profile and closes the file. P-073 (user decision):
`CloudWatch.AdditionalTags`/`ReplaceTags` are removed, because the metrics
CloudWatch sink no longer applies such tags; `AwsEndpoint` is keyed
`aws_endpoint` only, without the legacy `awsendpoint`/`AwsEndpoint` keys;
the `WaitOnExit` help text is fixed.

B23 (P-074, tlsconfig portion, and P-090 found by the reviews; the
`pkg/transport` portion of P-074 was fixed in B15). User decision: reject
insecure suites, reject TLS 1.3 names, keep the CHACHA20 aliases. The accepted names are the `tls.CipherSuites`
entries usable below TLS 1.3 plus the
`TLS_ECDHE_{RSA,ECDSA}_WITH_CHACHA20_POLY1305` aliases, built at `init`
from the Go release in use. Names in `tls.InsecureCipherSuites` (Go 1.27:
RC4, 3DES, CBC-SHA256 and all `TLS_RSA_*` suites) return
`insecure TLS cipher suite "<name>"`, TLS 1.3 names return
`TLS 1.3 cipher suite "<name>" is not configurable`, and other names keep
`unexpected TLS cipher suite "<name>"`; an alias is classified by its
canonical name. `GetCipherSuite` reports only accepted names. No opt-in
for insecure suites is provided. P-090 (found by the review and the PR 603
review): the `UpdateCipherSuites`, `gserver.TLSInfo` and `transport.TLSInfo`
comments describe the list as the enabled set only, because Go ignores the
order of `tls.Config.CipherSuites`; no preference-order option is added.

Migration: rename the CloudWatch `awsendpoint`/`AwsEndpoint` key to
`aws_endpoint`; delete `add_tags`/`replace_tags`; remove insecure and
TLS 1.3 names from `cipher_suites`.

| Batch                                      | Priority | Scope and intended result                                                                                                                                                                                                                                             | Findings                                                                    | Decision                                              |
| ------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------- |
| B24 — Coverage gate                        | P3       | Module tests: add behavior-focused tests for the untested packages and affected paths until total coverage exceeds the 90% CI gate.                                                                                                                                   | P-035                                                                       | None                                                  |
| B27 — Retriable TLS config precedence      | P3       | `pkg/retriable`: keep `ClientConfig.TLS` when an option replaces the transport in `New`, or reject the combination.                                                                                                                                                   | P-083                                                                       | TLS/transport precedence                              |
| B28 — HTTP metrics coverage                | P3       | `restserver`, `gserver`, `restserver/telemetry`: count responses produced before the metrics handler (identity 401, rate-limit 429, gserver preflights) and keep the `io.ReaderFrom` fast path through `ResponseCapture`.                                             | P-084, P-085                                                                | Metric coverage and `role` label                      |
| B29 — Roles provider lifetime              | P3       | `gserver/roles`: stop leaking the successful-lookup cache goroutine per `New`, without an API change if possible.                                                                                                                                                     | P-086                                                                       | None                                                  |
| B30 — Retriable refresh panic              | P3       | `pkg/retriable`: release caller-identity refresh waiters when the provider panics.                                                                                                                                                                                    | P-087                                                                       | None                                                  |

## Execution rules

1. Confirm each finding against the current code and add a regression test
   for its observable behavior. Preserve its ID until all portions of a
   multi-package finding are complete.
2. For rows with a **Decision**, record the selected behavior and any migration note
   before implementation. Findings marked Needs Approval retain that status
   until their decision is made; this plan does not grant approval.
3. Keep each code change reviewable. A multi-package batch may be delivered
   as linked package-scoped changes, with the same batch ID and a single
   final completion check. Update the codemap when entry points, ownership,
   invariants, configuration, or dependency directions change.
4. Run targeted package tests and affected consumers. For shared-state fixes,
   use a test with overlapping reads and writes and run `make test RACE=true`
   with Docker available for the Redis-backed tests. Benchmark performance
   fixes against the same scenario before and after; run race checks
   separately from timing.
5. Run `make testshort` and `make lint`; run the full `make test` suite with
   Docker for the final integrated change. Check the 90% coverage gate when
   completing B24 or changing coverage-sensitive code. Record any unavailable
   fixture or incomplete check.
6. When a batch is complete, remove its fixed findings from `FINDINGS.md`,
   remove the batch from this queue, and note public behavior changes in the
   next release notes. If only part of a finding is fixed, leave the ID and
   record the remaining portion here. Never reuse an ID.
