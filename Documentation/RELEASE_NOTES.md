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
