# RELEASE NOTES (current batch)

## Major fixes

- `gserver` rate limiting covers every protocol on every listener and is
  observable like other responses:
  - A limited REST request (HTTP 429) now goes through correlation, request
    metrics and the request logger, so it carries `X-Correlation-ID` and
    is an access-log line whose `remote` is the client IP the default
    limiter keys on (tollbooth groups an IPv6 client by its /64 prefix).
  - gRPC and gRPC-Web calls are limited by gRPC interceptors that share the
    listener's buckets. A limited call returns `ResourceExhausted` instead
    of HTTP 429, which gRPC clients saw as `Unavailable`. It is logged and
    counted in the gRPC metrics instead of the HTTP metrics, and gRPC-Web
    rejections keep their CORS headers.
  - Plaintext (h2c) gRPC, which cmux routes past the HTTP handler, is now
    rate limited.
  - A unary call draws its token before request validation, so requests
    that fail `Validate` no longer skip the limiter. They are now logged
    and counted in the gRPC metrics (P-099). A panic in `Validate` still
    fails the call with `Internal`, and is now logged and counted too.
  - Callers on a Unix socket have no client IP and are no longer limited
    by the default key; REST callers, and gRPC callers on `unixs://`, used
    to share one bucket. Set `headers_ip_lookups` without `RemoteAddr`
    when a proxy on the socket overwrites the forwarding headers;
    `RemoteAddr` keys every socket caller as `@`.
  - New `rate_limit.log_rejections`: logs one WARNING line per rejection
    with the limiter key, the socket peer, the User-Agent and the
    forwarding headers. Use it to check that a load balancer's client IP,
    and not its internal address, is the key.
- `gserver` gRPC and gRPC-Web log lines now report the caller (P-105). The
  log interceptor runs before identity extraction and read an empty
  request context, so every line had `"remote":""` and the
  `rpc_requests_role` metric labelled every call `guest`. Identity now
  hands its result back to the log interceptor: `remote` is the client IP
  resolved under `trusted_proxy_cidrs` and the metric carries the caller's
  role. A call rejected before or by identity (rate limit, validation, a
  bad credential) is logged with the same client IP and counted as
  `guest`. The gRPC `API_ERROR` and `INTERNAL_ERROR` lines now have
  `remote` too.

## Breaking changes (log fields and metric labels)

Log lines now use one name for each value: `remote` for the resolved
client IP, `peer` for the socket address (host:port), `agent` for the
User-Agent. Update log queries and dashboards that use the old names:

- gRPC log lines (`func=logRequest`, including `slow_request`): `ua` is
  now `agent`, and a call without a User-Agent logs `no-agent`, as REST
  does. `logger_skip_paths` still matches gRPC calls against the
  User-Agent as sent, so which calls are skipped (and get no gRPC
  metrics) is unchanged.
- `xhttp/identity` rejection lines: the HTTP `identityMapper` WARNING
  logs `remote` instead of `ip`; the gRPC `access_denied` WARNING now has
  `remote`.
- `gserver` `cors_not_allowed` and `debug_logs` lines: `remote` is now the
  resolved client IP instead of the socket address, which moves to
  `peer`, and `agent` is `no-agent` when the User-Agent is missing. The
  `pkg/transport` `set_keepalive` DEBUG line logs `peer` instead of
  `remote`.
- `rpc_requests_role` (`GRPCReqByRole`) counts calls under the caller's
  role instead of `guest`.

## Breaking changes (client IP type)

- `xhttp/identity.ClientIPFromRequest` and `ClientIPFromGRPC` return
  `netip.Addr` instead of `string`, so callers that need the address (a
  prefix check, a location lookup) no longer parse it back. A caller
  without an IP peer (no `RemoteAddr`, a Unix socket peer, a gRPC call
  without a peer) gets the zero `Addr`. Format the result with the new
  `identity.IPString`, which returns "" for it as before;
  `netip.Addr.String` returns "invalid IP".
- `identity.Context` (implemented by `RequestContext`) has a new
  `ClientAddr() netip.Addr`; `ClientIP()` still returns the string, ""
  when unknown. Other implementations of `Context` must add the method.
- Log field `remote` for a caller on a Unix socket is now empty instead
  of `@` (`"remote":""` in JSON; the text formatter omits it) in the REST
  access line, the gRPC lines, the `cors_not_allowed` and `debug_logs`
  lines and the `xhttp/identity` WARNING lines. `peer` still shows the
  socket address where it is logged.
- `identity.WithTestIdentity` also sets `ClientAddr`, and `FromRequest` no
  longer rewrites a context stored by `NewContextHandler` or the gRPC
  interceptors, so concurrent `FromRequest` calls in a handler are
  race-free for callers without a client IP or User-Agent.

## New features

- `restserver/telemetry.NoAgent` (`no-agent`): the agent the REST request
  logger logs and matches for a request without a User-Agent. The
  `gserver` gRPC, rate-limit, CORS and debug lines log it too.
- New `pkg/location`: the location (city, region, country) of a client
  IP. `Provider` is the lookup interface; `NewIPWhoIs` implements it with
  the ipwho.is JSON API (bounded timeout, no redirects, 4 KiB answers) and
  `NewCache` wraps any provider with an LRU of a configured size that
  shares one answer per IPv4 /24 or IPv6 /48 network (configurable), keeps
  answers for a TTL (24h by default), retries failed lookups and runs one
  lookup per network at a time. After an HTTP 429 the ipwho.is provider
  skips lookups until `Retry-After` and fails them with
  `ErrQuotaExceeded`. Private, loopback, carrier-grade NAT, IPv6 outside
  `2000::/3` and other special-purpose addresses are never looked up
  (`IsPublic`). `IPLocation` is a one-off lookup that logs and drops
  errors.
