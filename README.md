# porto

Server and client building blocks for Go services: a REST server, a combined
gRPC / gRPC-Web / REST server, HTTP helpers (errors, identity, correlation,
marshalling), and infrastructure packages (retrying HTTP client, gRPC client
builder, Redis client and cache, scheduler, TLS reloading, listeners,
application bootstrap).

Module: `github.com/effective-security/porto`. No binaries; import the
packages you need.

## Requirements

- Go 1.27 or later (`go.mod` sets `go 1.27`; the standard `uuid` package is used).
- Docker, only to run the Redis-backed tests (`pkg/redisclient`, `pkg/cache`).

```sh
go get github.com/effective-security/porto@latest
```

## Packages

| Package                                     | Purpose                                                                                                                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `restserver`                                | httprouter-based HTTP/HTTPS server hosting `Service` plug-ins with correlation ID, identity, metrics, logging, authz, readiness and CORS middleware.                            |
| `restserver/authz`                          | Path-segment/role access control tree (YAML-configurable) exposed as an HTTP handler and gRPC interceptors.                                                                     |
| `restserver/ready`                          | Readiness-gate middleware answering 503 `not_ready` until the server reports ready.                                                                                             |
| `restserver/telemetry`                      | Request logger and request metrics middleware with skip-path filters.                                                                                                           |
| `gserver`                                   | Combined gRPC + gRPC-Web + REST server with cmux multiplexing, TLS reload, CORS, rate limiting, identity/authz middleware and graceful shutdown.                                |
| `gserver/credentials`                       | gRPC credential bundle: TLS transport credentials plus per-RPC Bearer/DPoP/AWS tokens with automatic refresh.                                                                   |
| `gserver/roles`                             | Identity provider mapping JWT, DPoP, AWS STS and TLS/SPIFFE callers to roles for HTTP and gRPC.                                                                                 |
| `xhttp/correlation`                         | Correlation/request ID propagation across HTTP headers, gRPC metadata, contexts and logs.                                                                                       |
| `xhttp/header`                              | HTTP header name and content-type constants.                                                                                                                                    |
| `xhttp/httperror`                           | Structured API errors with HTTP status, code, gRPC status and request ID, plus gRPC ↔ HTTP mapping.                                                                             |
| `xhttp/identity`                            | Caller identity, client IP and user agent extraction into request contexts for HTTP and gRPC.                                                                                   |
| `xhttp/limits` | Shared HTTP, protocol detection and TLS handshake timeout defaults and body-size defaults. |
| `xhttp/marshal`                             | JSON response writing (errors, gzip, pretty print) and strict JSON request decoding.                                                                                            |
| `pkg/retriable`                             | HTTP client with retry policy, JSON marshalling, header propagation, Bearer/DPoP auth, replay nonces and token storage. See [pkg/retriable/README.md](pkg/retriable/README.md). |
| `pkg/rpcclient`                             | gRPC client builder: TLS bundle, per-RPC Bearer/DPoP tokens, keepalive, message limits, optional blocking dial.                                                                 |
| `pkg/redisclient`                           | Prefixed go-redis wrapper with JSON values, bounded collections, a distributed lock and a per-window rate limiter.                                                              |
| `pkg/cache`                                 | `Provider` cache abstraction (TTL, keys, pub/sub) with in-memory, Redis and prefixing-proxy backends.                                                                           |
| `pkg/tasks`                                 | In-process cron-like scheduler: run functions every N units, daily at hh:mm, or weekly, with overlap protection.                                                                |
| `pkg/tlsconfig`                             | Build `tls.Config` from PEM files (TLS 1.2+, h2) with OCSP staple support and a file-polling certificate reloader.                                                              |
| `pkg/transport`                             | TLS listener with eager handshake and CRL checks, keepalive listeners, and file-based `TLSInfo` server config.                                                                  |
| `pkg/appinit`                               | Service bootstrap: logging flags and rotation, Prometheus/CloudWatch metrics, CPU profiling.                                                                                    |
| `pkg/appinit/config`                        | YAML/JSON config struct for the metrics pipeline.                                                                                                                               |
| `pkg/discovery`                             | Minimal in-process service registry resolved by interface.                                                                                                                      |
| `pkg/crlcache`                              | `Verifier` interface for certificate revocation checks.                                                                                                                         |
| `pkg/streamctx`                             | Override a gRPC `ServerStream` context in interceptors.                                                                                                                         |
| `metricskey`                                | Metric descriptors emitted by the servers.                                                                                                                                      |
| `tests/testutils`, `tests/mockappcontainer` | Test helpers: free ports, JSON comparison, dig container builder.                                                                                                               |

Every package has a `doc.go` with a usage example. The generated API
reference lives in [Documentation/api](Documentation/api) (`make docs`), and
the navigation index for the code is
[Documentation/codemap.md](Documentation/codemap.md).

## Quick start

### REST server

```go
type cfg struct{ bind, name, public string }

func (c cfg) GetServerName() string { return c.name }
func (c cfg) GetBindAddr() string   { return c.bind }
func (c cfg) GetPublicURL() string  { return c.public }
func (c cfg) GetServices() []string { return nil }

type hello struct{}

func (hello) Name() string  { return "hello" }
func (hello) IsReady() bool { return true }
func (hello) Close()        {}
func (hello) Register(r restserver.Router) {
	r.GET("/v1/hello/:name", func(w http.ResponseWriter, req *http.Request, p restserver.Params) {
		marshal.WriteJSON(w, req, map[string]string{"hello": p.ByName("name")})
	})
}

srv, err := restserver.New("1.0.0", "", cfg{bind: ":8080", name: "api"}, nil) // nil TLS = plain HTTP
if err != nil {
	log.Fatal(err)
}
srv.WithCORS(&restserver.CORSOptions{AllowedOrigins: []string{"*"}})
srv.AddService(hello{})
if err := srv.StartHTTP(); err != nil {
	log.Fatal(err)
}
defer srv.StopHTTP()
```

Authorization is configured in YAML and attached with `WithAuthz`:

```yaml
authz:
  allow:
    - /v1/admin:admin
    - /v1/items:admin,user
  allow_any:
    - /v1/status
  allow_any_role:
    - /v1/me
  log_denied: true
```

```go
az, err := authz.New(&cfg.Authz)
if err != nil {
	return err
}
srv.WithAuthz(az).WithIdentityProvider(myMapper) // identity.ProviderFromRequest
```

### Handlers: errors, decoding, identity

```go
func (s *svc) get(w http.ResponseWriter, r *http.Request, p restserver.Params) {
	var req ItemRequest
	if marshal.DecodeBody(w, r, &req) != nil {
		return // 400 invalid_json already written
	}
	if req.ID == "" {
		marshal.WriteJSON(w, r, httperror.InvalidParam("id is required"))
		return
	}
	caller := identity.FromRequest(r)
	item, err := s.store.Get(r.Context(), caller.Identity().Tenant(), req.ID)
	if err != nil {
		marshal.WriteJSON(w, r, httperror.WrapWithCtx(r.Context(), err, "load %s", req.ID)) // 404/408/500
		return
	}
	marshal.WriteJSON(w, r, item) // 200 application/json, gzip when accepted
}
// error body: {"code":"not_found","message":"load 42","request_id":"a1b2c3d4e5f6"}
```

### gRPC + gRPC-Web + REST server

```go
cfg := &gserver.Config{
	ListenURLs: []string{"https://0.0.0.0:8443"},
	Services:   []string{"status"},
	ServerTLS: &gserver.TLSInfo{
		CertFile:     "server.pem",
		KeyFile:      "server-key.pem",
		ClientCAFile: "ca.pem",
	},
	IdentityMap: &roles.IdentityMap{
		JWT: roles.JWTIdentityMap{
			Enabled:                  true,
			Issuer:                   "https://issuer",
			Audience:                 "api",
			DefaultAuthenticatedRole: roles.JWTUserRoleName,
		},
	},
	Authz: &authz.Config{AllowAny: []string{"/healthz"}, Allow: []string{"/v1:jwt_user,admin"}},
}
factories := map[string]gserver.ServiceFactory{
	"status": func(s gserver.GServer) any {
		return func() { s.AddService(status.New(s)) } // implements Service + RouteRegistrator/GRPCRegistrator
	},
}
srv, err := gserver.Start("api", cfg, container, factories, gserver.WithMiddleware(myMiddleware))
if err != nil {
	log.Fatal(err)
}
defer srv.Close()
select {
case err := <-srv.Err():
	log.Fatal(err)
case <-ctx.Done():
}
```

The same server from YAML:

```yaml
listen_urls: ["https://0.0.0.0:8443", "unix:///var/run/api.sock"]
services: ["status", "api"]
server_tls:
  cert: /etc/tls/server.pem
  key: /etc/tls/server-key.pem
  client_ca: /etc/tls/ca.pem
cors:
  enabled: true
  allowed_origins: ["https://app.example.com"]
  allow_credentials: true
rate_limit:
  enabled: true
  requests_per_second: 100
timeout:
  request: 10s
identity_map:
  skip_auth: ["/healthz"]
  jwt:
    enabled: true
    issuer: https://issuer
    audience: api
    default_authenticated_role: jwt_user
    roles:
      admin: ["alice@example.com"]
  tls:
    enabled: true
    default_authenticated_role: tls_user
    roles:
      admin: ["spiffe://trust/ns/ops"]
authz:
  allow_any: ["/healthz"]
  allow: ["/v1:jwt_user,admin", "/pb.API/:admin"]
```

Client IPs use the socket peer by default; `X-Forwarded-Proto` is ignored
unless the peer is trusted. When a
reverse proxy overwrites incoming forwarding headers, configure
`trusted_proxy_cidrs` with its network ranges (for example,
`["10.2.0.0/16"]`). The default rate limiter then uses the resolved client
IP. `restserver.HTTPServer` supports the same policy; set it before
`StartHTTP`:

```go
trust, err := identity.ParseTrustedProxies([]string{"10.2.0.0/16"})
if err != nil {
	return err
}
srv.WithTrustedProxies(trust)
```

### HTTP client with retries

```go
client, err := retriable.New(retriable.ClientConfig{
	Host:    "https://api.example.com",
	Request: &retriable.RequestPolicy{RetryLimit: 3, Timeout: 5 * time.Second},
}, retriable.WithUserAgent("my-cli"))
if err != nil {
	return err
}
if err := client.Config.LoadAuthTokenOrFromEnv("MY_TOKEN"); err == nil {
	_ = client.SetAuthorization() // Authorization: Bearer or DPoP
}
var res struct {
	ID string `json:"id"`
}
_, status, err := client.Get(ctx, "/v1/items/1", &res)
```

```yaml
# retriable.LoadFactory(file)
clients:
  prod:
    host: https://api.example.com
    tls:
      trusted_ca: /etc/pki/cabundle.pem
    request:
      retry_limit: 3
      timeout: 2s
    storage_folder: ~/.config/demo
```

### gRPC client

```go
cfg := &rpcclient.Config{
	Endpoint:    "https://api.example.com:443", // TLS requires https:// or unixs://
	TLS:         tlsCfg,
	DialTimeout: 5 * time.Second, // 0 = lazy connect
}
if err := cfg.LoadAuthTokenOrFromEnv("MY_TOKEN"); err != nil {
	return err
}
client, err := rpcclient.New(cfg)
if err != nil {
	return err
}
defer client.Close()
svc := pb.NewMyServiceClient(client.Conn())
res, err := svc.Call(ctx, req, client.Opts()...)
```

### Redis and cache

```go
rc, err := redisclient.New(&redisclient.Config{Server: "redis://localhost:6379/0", Password: "secret"})
if err != nil {
	return err
}
defer rc.Close()
c := rc.WithPrefix("myapp")                 // keys under /myapp/
_ = c.Set(ctx, "user:1", user, time.Hour)  // JSON encoded
var u User
if err := c.Get(ctx, "user:1", &u); redisclient.IsNotFoundError(err) {
	// miss
}
ok, ttl, err := c.TryLock(ctx, "job", 30*time.Second)
```

```go
var p cache.Provider
if cfg.Provider == "redis" {
	p, err = cache.NewRedisProvider(*cfg.Redis, "/myapp")
} else {
	p = cache.NewMemoryProvider("/myapp")
}
_ = p.Set(ctx, "user:1", user, 10*time.Minute) // 0 => default TTL, cache.KeepTTL => no expiry
err = p.Get(ctx, "user:1", &u)                  // cache.IsNotFoundError(err) on miss
users := cache.NewProxyProvider("users", p)     // sub-namespace sharing the connection
```

### Scheduler

```go
s := tasks.NewScheduler(tasks.WithTickerInterval(time.Second))
s.Add(tasks.NewTaskAtIntervals(30, tasks.Seconds).Do("cleanup", cleanup))
s.Add(tasks.NewTaskDaily(2, 30).Do("rotate", rotate, "/var/log"))
t, err := tasks.NewTask("every day 11:15")
if err != nil {
	return err
}
s.Add(t.Do("report", report))
if err := s.Start(); err != nil {
	return err
}
defer s.Stop()
```

### TLS listeners with certificate reload

```go
info := &transport.TLSInfo{
	CertFile:       "server.pem",
	KeyFile:        "server-key.pem",
	TrustedCAFile:  "ca.pem",
	ClientAuthType: tls.VerifyClientCertIfGiven,
}
defer info.Close()
ln, _ := net.Listen("tcp", ":8443")
tlsLn, err := transport.NewTLSListener(ln, info) // keypair reloaded every 5 minutes
if err != nil {
	return err
}
srv := &http.Server{Handler: h, TLSConfig: info.Config(), ReadHeaderTimeout: 10 * time.Second}
return srv.Serve(tlsLn)
```

```go
// client-side mTLS with rotation
cfg, reloader, err := tlsconfig.NewClientTLSWithReloader("client.pem", "client-key.pem", "ca.pem", 5*time.Minute)
if err != nil {
	return err
}
defer reloader.Close()
client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
```

### Application bootstrap

```yaml
metrics:
  provider: prometheus
  prefix: myservice
  global_tags: [service, cluster_id]
  prometheus:
    addr: :9090
    expiration: 5m
```

```go
lc, err := appinit.Logs(&flags.LogConfig, "myservice") // --log-dir enables rotation
if err != nil {
	return err
}
if lc != nil {
	defer lc.Close()
}
mc, err := appinit.Metrics(&cfg.Metrics, "myservice", cluster, version, commit, nil)
if err != nil {
	return err
}
if mc != nil {
	defer mc.Close()
}
```

## Development

- `make tools` installs golangci-lint, cov-report, govulncheck and gomarkdoc into `bin/`.
- `make test` runs the tests (Docker required for the Redis packages); `make test RACE=true` adds the race detector.
- `make testshort` skips the slow tests; `make covtest coverage` produces and opens the coverage report.
- `make lint` runs gofmt (with the project rewrites), `go vet`, `govulncheck` and `golangci-lint`.
- `make docs` regenerates the API reference under `Documentation/api/`.
- `make all` runs clean, tools, generate and covtest.

CI runs `make build covtest` and requires 90% total coverage. Conventions
for contributors and agents are in [AGENTS.md](AGENTS.md); known defects
are tracked in [FINDINGS.md](FINDINGS.md) and larger work in
[ROADMAP.md](ROADMAP.md).

## Server network limits

HTTP servers now default to 10s for headers, 30s for whole-request reads,
60s idle and 10 MiB for request bodies. cmux detection and eager TLS
handshakes default to 10s. Zero selects a default; negative values disable
individual limits. Header deadlines use native net/http semantics: HTTP/2 has no per-stream
header deadline. There is no response write deadline. Raise or disable
read/body limits for large uploads and long request streams.

`gserver.Config` accepts `timeouts: {header: 10s, read: 30s, idle: 60s,
handshake: 10s}` and `max_request_body: 10485760` in YAML. The existing
`timeout.request` still controls shutdown only. Native gRPC on plaintext
listeners retains its per-message limits; HTTP body limits also apply to
TLS gRPC/gRPC-Web streams. Native gRPC streams have no read deadline, so
long-lived client and bidi streams work on both listener types; on TLS a
stream fails with `Unavailable` once it has sent `max_request_body` bytes in
total.

For REST, configure `WithTimeouts(limits.Timeouts{...})` and
`WithMaxRequestBody(bytes)` before `StartHTTP`. Both default and custom muxes
are bounded. Native net/http TLS uses the smaller positive header/read
value for its handshake; the Handshake field is for cmux/eager listeners.
`transport.TLSInfo.HandshakeTimeout` overrides the eager TLS deadline.

`marshal.DecodeBody` also enforces the body default when used alone.
`marshal.LimitRequestBody(handler, bytes)` overrides it. The limiter writes
no response, so it cannot bypass CORS, correlation, logging or metrics. A body
with a known oversized `Content-Length` fails on its first read before any
byte is read. `DecodeBody` answers it, and any oversized JSON body, with HTTP
413 `request_too_large`. Other handlers that read bodies must handle
`*http.MaxBytesError`. Over gRPC, `request_too_large` travels as
`ResourceExhausted`; `httperror.NewFromPb` restores the 413 from the code
detail that `GRPCStatus` attaches.

Prometheus accepts the same `timeouts` and `max_request_body` fields inside
its metrics config block. `appinit.Metrics` returns bind errors synchronously;
callers must handle them and close its returned closer to stop the endpoint.
