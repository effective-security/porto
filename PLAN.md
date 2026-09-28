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

| Batch                                      | Priority | Scope and intended result                                                                                                                                                                                                                                             | Findings                                                                    | Decision                                              |
| ------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------- |
| B07 — gserver lifecycle and rate setup     | P2       | `gserver`: close failed serve channels and TLS reloaders reliably; validate enabled rate limits before serving.                                                                                                                                                       | P-003, P-004, P-006                                                         | Rate-limit configuration behavior                     |
| B10 — HTTP errors and authorization        | P2       | `xhttp/httperror`, `xhttp/marshal`, `xhttp/identity`, `restserver/ready`, `restserver/authz`: remove shared error mutation, return 403 for forbidden access, avoid denial double-wrapping and internal error disclosure, and constrain the OPTIONS bypass.            | P-016, P-027, P-028, P-029, P-032, P-033                                    | Auth and error response changes                       |
| B11 — Cache pub/sub                        | P2       | `pkg/cache`: prevent blocked or leaked subscription goroutines, define publish behavior for slow consumers, and stabilize the Redis pub/sub test.                                                                                                                     | P-041, P-042, P-075                                                         | Slow-subscriber policy                                |
| B12 — Redis coordination and secrets       | P2       | `pkg/redisclient`: make rate-limit windows atomic and non-starving, make lock release owner-bound, redact connection logging, and fix close and eviction error handling.                                                                                              | P-043, P-045, P-047, P-062, P-063                                           | Rate-limit, lock, and close semantics                 |
| B13 — Key namespaces                       | P2       | `pkg/redisclient`, `pkg/cache`: prevent `..` from escaping a prefix and align memory/Redis `Keys` prefix and pattern behavior.                                                                                                                                        | P-044, P-064                                                                | Key layout and pattern contract                       |
| B15 — TLS listener and policy              | P2       | `pkg/transport`: enforce or remove documented `TLSInfo` checks, preserve temporary accept errors, and modernize keepalive configuration. Handshake deadlines are in B06.                                                                                              | P-052, P-053, P-074 (transport portion)                                     | TLSInfo contract                                      |
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
