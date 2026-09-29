# retriable

HTTP client with retry policy, JSON marshalling, header propagation,
Bearer/DPoP authorization, replay nonces and file-based token storage.

## Creating a client

```go
client, err := retriable.New(retriable.ClientConfig{
	Host: "https://api.example.com",
	Request: &retriable.RequestPolicy{RetryLimit: 3, Timeout: 5 * time.Second},
}, retriable.WithUserAgent("my-cli"))
if err != nil {
	return err
}

var res struct{ ID string `json:"id"` }
hdr, status, err := client.Get(ctx, "/v1/items/1", &res)
```

Clients can also be loaded from YAML: `LoadClient(file)` reads a single
`ClientConfig`, `LoadFactory(file)` reads a `Config` with named clients and
`Factory.CreateClient(name)` / `Factory.ForHost(url)` build them.

```yaml
clients:
  prod:
    host: https://api.example.com
    tls:
      cert: ~/.config/demo/client.pem
      key: ~/.config/demo/client.key
      trusted_ca: /etc/pki/cabundle.pem
    request:
      retry_limit: 3
      timeout: 2s
    storage_folder: ~/.config/demo
```

## Interfaces

`*Client` implements `HTTPClientWithNonce`, which is the union of:

```go
// GenericHTTP defines request helpers that take an explicit host.
type GenericHTTP interface {
	// Request sends a request to the specified host and decodes the response
	// into responseBody. Statuses >= 300 (except 204) are returned as an error.
	//
	// host should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
	// path should be an absolute URI path, i.e. /foo/bar/baz
	// requestBody can be io.Reader, []byte, string, or an object to be JSON encoded
	// responseBody can be io.Writer, or a struct to decode JSON into.
	Request(ctx context.Context, method string, host string, path string, requestBody any, responseBody any) (http.Header, int, error)

	// RequestURL is similar to Request but takes a raw URL.
	RequestURL(ctx context.Context, method, rawURL string, requestBody any, responseBody any) (http.Header, int, error)

	// HeadTo makes a HEAD request against the specified host.
	HeadTo(ctx context.Context, host string, path string) (http.Header, int, error)
}

// HTTPClient groups the helpers that use the configured host.
type HTTPClient interface {
	Head(ctx context.Context, path string) (http.Header, int, error)
	Get(ctx context.Context, path string, body any) (http.Header, int, error)
	Post(ctx context.Context, path string, requestBody any, responseBody any) (http.Header, int, error)
	Put(ctx context.Context, path string, requestBody any, responseBody any) (http.Header, int, error)
	Delete(ctx context.Context, path string, body any) (http.Header, int, error)
}
```

`Client.Do(*http.Request)` is the lower-level entry point (implements
`Requestor`): it applies headers, auth and retries and returns the raw
response, which the caller must close.

## Retry policy

`Policy.Retries` maps an HTTP status (0 for transport errors) to a
`ShouldRetry` callback; `TotalRetryLimit` caps retries across all codes and
`RequestTimeout` bounds each `Request`/`Get`/... call (not `Do`).
`DefaultPolicy()` allows 5 retries in total: connection errors up to 4 times
(2s wait), 502 and 503 up to 5 times (1s), and 429 up to 3 times after the
response's `Retry-After` (1s without one). A 429 whose `Retry-After` asks for
more than 30s is returned at once with reason `LimitExceeded`, as is a 429
under a policy without a 429 entry. DNS/TLS errors, 404 and other 4xx are
never retried. `RetryAfterShouldRetryFactory(limit, wait, maxWait, reason)`
builds the same `Retry-After` handling for custom policies (for example 503).

The wait between attempts ends when the request context is done, and `Do`
returns the context error; while the context is live, a retry that could
not start before its deadline is skipped and the last response is returned. A retried response
body is drained (up to 64 KiB) and closed; an error response body is read up
to 64 KiB into the returned error.

In a `ClientConfig`, `request.retry_limit` and `request.timeout` replace the
`DefaultPolicy` values only when non-zero; a negative `retry_limit` disables
retries.

```go
client.WithPolicy(retriable.Policy{
	TotalRetryLimit: 3,
	RequestTimeout:  time.Second,
	Retries: map[int]retriable.ShouldRetry{
		http.StatusServiceUnavailable: retriable.DefaultShouldRetryFactory(2, time.Millisecond, "retry"),
	},
})
```

## Headers and context

- `WithHeaders(ctx, map)` / `PropagateHeadersFromRequest(ctx, r, names...)`
  attach headers to a context; the client sets them on outgoing requests.
- `X-Correlation-ID` is added from the context (`xhttp/correlation`) when absent.
- `WithUserAgent(name)` adds `User-Agent`, `X-CLIENT-HOSTNAME`, `X-CLIENT-IP`
  without waiting for the network; a host name or IP that cannot be resolved
  is not sent.

## Transport

`WithTLS(cfg)` and `WithDNSServer(addr)` install a modified clone of the
current `*http.Transport` (of `http.DefaultTransport` when none is set), so a
transport passed to `WithTransport` is never changed. Call them after
`WithTransport`, which replaces the transport with all its settings. On any
other `http.RoundTripper` they cannot apply their setting: `New` returns the
error, and after `New` every request fails with it until `WithTransport`
replaces the transport. When a transport the client created is replaced, its
idle connections are closed; a transport passed to `WithTransport` is never
closed by the client. Note that a `WithTransport` option passed to `New`
replaces the transport built from `ClientConfig.TLS` (FINDINGS P-083).

`RequestURL` derives the host and request URI from the parsed URL and
rejects URLs without a scheme, opaque URLs (`https:host/path`) and URLs with
user info (credentials).

## Authorization and storage

`Storage` (root = `ClientConfig.StorageFolder`) keeps `.auth_token` and DPoP
keys (`<thumbprint>.jwk`). Load the token with
`ClientConfig.LoadAuthTokenOrFromEnv("MY_TOKEN")` or `LoadAuthToken()`, then
call `client.SetAuthorization()` to add the `Authorization` header; DPoP
tokens are signed per request. Token format is an opaque string or
`access_token=...&exp=<unix>&dpop_jkt=<jkt>&token_type=DPoP`.
Authorization is only sent to `https://` and `unixs://` hosts.

New credentials folders use mode `0700`; existing folder permissions are kept.
An empty storage path uses the working directory. Token and key files use `0600`.
DPoP proofs are signed separately for each retry attempt.

## Nonces

`client.WithNonce("/nonce", retriable.DefaultReplayNonceHeader)` installs a
`NonceProvider` that caches nonces from response headers and fetches new
ones with HEAD requests; it satisfies `jose.NonceSource`. `NonceContext(ctx)`
bounds a fetch by `ctx`; `Nonce()` (which has no context) bounds it by 30s.
The cache keeps the newest nonces: when its 64 entries are full, the oldest
half is dropped.
