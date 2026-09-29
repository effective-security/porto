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

| Batch                                      | Priority | Scope and intended result                                                                                                                                                                                                                                             | Findings                                                                    | Decision                                              |
| ------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------- |
| B12 — Redis coordination and secrets       | P2       | `pkg/redisclient`: make rate-limit windows atomic and non-starving, make lock release owner-bound, redact connection logging, and fix close and eviction error handling.                                                                                              | P-043, P-045, P-047, P-062, P-063                                           | Rate-limit, lock, and close semantics                 |
| B13 — Key namespaces                       | P2       | `pkg/redisclient`, `pkg/cache`: prevent `..` from escaping a prefix and align memory/Redis `Keys` prefix and pattern behavior.                                                                                                                                        | P-044, P-064                                                                | Key layout and pattern contract                       |
| B15 — TLS listener and policy              | P2       | `pkg/transport`: enforce or remove documented `TLSInfo` checks, preserve temporary accept errors, stop caching a half-built server TLS config after an error, and modernize keepalive configuration. Handshake deadlines are in B06.                                  | P-052, P-053, P-074 (transport portion), P-080                              | TLSInfo contract                                      |
| B16 — HTTP client retry behavior           | P2       | `pkg/retriable`: preserve the default retry limit, make backoff and context cancellation correct, handle 429 and nonce retries, avoid transport type panics/mutation, fix URL parsing, path expansion, and the blocking network wait, and bound error-body reads.     | P-046, P-056, P-057, P-058, P-060, P-061, P-065, P-066 (remaining portions) | Retry and transport behavior                          |
| B17 — HTTP telemetry and response writer   | P2       | `restserver/telemetry`: use bounded route labels, expose the underlying writer for upgrades/controllers, and guard zero granularity.                                                                                                                                  | P-023, P-024, P-031                                                         | Metric label contract                                 |
| B19 — Caller credentials and role handling | P3       | `gserver/credentials`, `gserver/roles`: synchronize credential refresh, repair `NewWithMode`, remove CSRF values from logs, add bounded negative STS caching, and enforce cookie CSRF consistently.                                                                   | P-009, P-010, P-013, P-014, P-015                                           | Cookie/CSRF contract                                  |
| B21 — App initialization                   | P3       | `pkg/appinit`, `pkg/appinit/config`: cancel the CloudWatch runner, handle CPU profile start/close errors, and resolve unused CloudWatch config fields and help text.                                                                                                  | P-067, P-068, P-073                                                         | Config-field behavior                                 |
| B23 — TLS cipher names                     | P3       | `pkg/tlsconfig`: derive supported cipher names from Go's TLS API and reject insecure suites.                                                                                                                                                                          | P-074 (tlsconfig portion)                                                   | Cipher/config compatibility                           |
| B24 — Coverage gate                        | P3       | Module tests: add behavior-focused tests for the untested packages and affected paths until total coverage exceeds the 90% CI gate.                                                                                                                                   | P-035                                                                       | None                                                  |

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
