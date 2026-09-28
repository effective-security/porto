# Code map

Navigation index for agents and new contributors: concept → file → entry
points → invariants. Start here instead of grepping the tree. If you had to
grep for something that belongs in this map, add the row in the same change
(see [AGENTS.md](../AGENTS.md)).

- High level purpose and samples: [README.md](../README.md)
- Known defects, with IDs referenced from code comments: [FINDINGS.md](../FINDINGS.md)
- Larger planned work: [ROADMAP.md](../ROADMAP.md)
- Generated API reference (`make docs`): [api/](api/)

## Module layout

```
gserver/            gRPC + gRPC-Web + REST server (cmux), identity + authz wiring
  credentials/      gRPC credential bundle (TLS + Bearer/DPoP per-RPC tokens)
  roles/            identity provider: JWT, DPoP, AWS STS, TLS/SPIFFE → roles
restserver/         httprouter REST server with fixed middleware chain
  authz/            path/role access control tree (HTTP handler + gRPC interceptors)
  ready/            readiness gate middleware
  telemetry/        request logger, request metrics, ResponseCapture
xhttp/
  correlation/      correlation ID across HTTP, gRPC metadata, context, logs
  header/           header name and content-type constants
  httperror/        structured API errors, HTTP ↔ gRPC code mapping
  identity/         caller identity + client IP in request contexts
  marshal/          JSON response writing (gzip, ?pp) and strict decoding
pkg/
  retriable/        HTTP client: retry policy, failover, Bearer/DPoP, nonces, token storage
  rpcclient/        gRPC client builder from Config
  redisclient/      prefixed go-redis wrapper, lock, rate limiter
  cache/            Provider abstraction: memory, Redis, proxy; pub/sub
  tasks/            cron-like scheduler
  tlsconfig/        tls.Config from files, KeypairReloader, HTTPTransport
  transport/        TLS listener (eager handshake, CRL), keepalive listener, TLSInfo
  appinit/          logging, metrics (Prometheus/CloudWatch), CPU profiler; config/
  discovery/        in-process service registry by interface
  crlcache/         Verifier interface for revocation checks
  streamctx/        override grpc.ServerStream context
metricskey/         metric descriptors
tests/              testutils (free ports, JSON compare), mockappcontainer (dig builder)
```

### Internal dependency direction

Arrows point from importer to imported. Nothing under `xhttp/` or `pkg/`
imports `restserver` or `gserver`, except `pkg/retriable`, `pkg/rpcclient`,
`pkg/cache` and `pkg/redisclient`, which import `gserver/credentials`
(token types) or `gserver` (`TLSInfo`) only.

| Package                                                                                                                         | Imports from this module                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gserver`                                                                                                                       | `gserver/credentials`, `gserver/roles`, `pkg/discovery`, `pkg/transport`, `restserver/authz`, `restserver/ready`, `restserver/telemetry`, `xhttp/*`, `metricskey` |
| `gserver/roles`                                                                                                                 | `gserver/credentials`, `xhttp/header`, `xhttp/identity`                                                                                                           |
| `gserver/credentials`                                                                                                           | none                                                                                                                                                              |
| `restserver`                                                                                                                    | `restserver/authz`, `restserver/ready`, `restserver/telemetry`, `xhttp/*`                                                                                         |
| `restserver/authz`                                                                                                              | `restserver/telemetry`, `xhttp/httperror`, `xhttp/identity`, `xhttp/marshal`                                                                                      |
| `restserver/ready`                                                                                                              | `xhttp/httperror`, `xhttp/marshal`                                                                                                                                |
| `restserver/telemetry`                                                                                                          | `metricskey`, `xhttp/header`, `xhttp/identity`                                                                                                                    |
| `xhttp/correlation`                                                                                                             | `pkg/streamctx`, `xhttp/header`                                                                                                                                   |
| `xhttp/httperror`                                                                                                               | `xhttp/correlation`, `xhttp/header`                                                                                                                               |
| `xhttp/identity`                                                                                                                | `pkg/streamctx`, `xhttp/header`, `xhttp/httperror`, `xhttp/marshal`                                                                                               |
| `xhttp/marshal`                                                                                                                 | `xhttp/header`, `xhttp/httperror`                                                                                                                                 |
| `pkg/retriable`                                                                                                                 | `gserver/credentials`, `pkg/tlsconfig`, `xhttp/correlation`, `xhttp/header`, `xhttp/httperror`                                                                    |
| `pkg/rpcclient`                                                                                                                 | `gserver/credentials`, `pkg/retriable`, `xhttp/httperror`                                                                                                         |
| `pkg/redisclient`, `pkg/cache`                                                                                                  | `pkg/tlsconfig` (and `gserver.TLSInfo` for config)                                                                                                                |
| `pkg/transport`                                                                                                                 | `pkg/crlcache`, `pkg/tlsconfig`                                                                                                                                   |
| `pkg/appinit`                                                                                                                   | `pkg/appinit/config`, `metricskey`                                                                                                                                |
| `tests/mockappcontainer`                                                                                                        | `gserver`, `pkg/discovery`                                                                                                                                        |
| `xhttp/header`, `pkg/tlsconfig`, `pkg/tasks`, `pkg/discovery`, `pkg/crlcache`, `pkg/streamctx`, `metricskey`, `tests/testutils` | none                                                                                                                                                              |

## Concept index

| Concept                                     | Package                                    | File                             | Symbol                                                                     |
| ------------------------------------------- | ------------------------------------------ | -------------------------------- | -------------------------------------------------------------------------- |
| gRPC/REST/gRPC-Web server bootstrap         | gserver                                    | server.go                        | `Start`, `GServer`                                                         |
| listen URL schemes (http/https/unix/unixs)  | gserver                                    | serve.go                         | `configureListeners`                                                       |
| cmux protocol multiplexing (HTTP1 vs HTTP2) | gserver                                    | serve.go                         | `serveCtx.serve`                                                           |
| gRPC-Web translation / trailer frame        | gserver                                    | grpc_web_response.go             | `grpcWebResponse`, `buildTrailerFrame`                                     |
| gRPC-Web text (base64)                      | gserver                                    | grpc_web_response.go             | `writeTextPayload`                                                         |
| gRPC-Web gzip / `X-GRPC-Stream`             | gserver                                    | serve.go                         | `grpcHandlerFunc`                                                          |
| CORS (REST, rs/cors)                        | gserver, restserver                        | serve.go, router.go              | `configureHandlers`, `corsHandler`, `CORSOptions`, `NewRouterWithCORS`     |
| CORS (gRPC-Web headers)                     | gserver                                    | serve.go, grpc_web_response.go   | `grpcHandlerFunc`, `grpcWebResponse.prepareHeaders`, `mergeVaryHeader`     |
| rate limit (tollbooth)                      | gserver                                    | serve.go, config.go              | `configureRateLimiter`, `RateLimit`                                        |
| trusted proxy CIDRs / forwarding headers    | xhttp/identity, gserver, restserver        | realip.go, config.go, server.go  | `ParseTrustedProxies`, `WithTrustedProxies`, `NewTrustedProxyHandler`, `Config.Validate`, `HTTPServer.WithTrustedProxies` |
| client IP resolved once per request         | xhttp/identity                             | realip.go                        | `NewTrustedProxyHandler`, `ClientIPFromRequest`, `forwarding`              |
| HTTP middleware chain order                 | gserver, restserver                        | serve.go, server.go              | `configureHandlers`, `HTTPServer.NewMux`                                   |
| gRPC interceptor chain                      | gserver                                    | serve.go                         | `grpcServer`                                                               |
| panic recovery                              | gserver, xhttp/correlation, xhttp/identity | serve.go, correlation.go, ctx.go | `panicInterceptor`, `NewAuthUnaryInterceptor`                              |
| request validation (`Validate()`)           | gserver                                    | serve.go                         | `NewRequestValidationUnaryInterceptor`, `Validator`                        |
| keepalive (gRPC server)                     | gserver                                    | serve.go, config.go              | `configureListeners`, `KeepAliveCfg`                                       |
| keepalive (gRPC client)                     | pkg/rpcclient                              | config.go                        | `Config.DialKeepAliveTime/Timeout`                                         |
| keepalive (TCP listener)                    | pkg/transport                              | keepalive_listener.go            | `NewKeepAliveListener`                                                     |
| TLS server config / client cert auth        | gserver, pkg/transport                     | config.go, tls.go                | `TLSInfo`, `TLSInfo.ServerTLSWithReloader`                                 |
| TLS reload / certificate rotation           | pkg/tlsconfig                              | reloader.go                      | `KeypairReloader`, `GetKeypairFunc`                                        |
| TLS min version / ALPN defaults             | pkg/tlsconfig                              | tlsconfig.go                     | `NewServerTLSFromFiles`, `NewClientTLSFromFiles`                           |
| mutual TLS client (`GetClientCertificate`)  | pkg/tlsconfig                              | tlsconfig.go                     | `NewClientTLSWithReloader`                                                 |
| cipher suites by name                       | pkg/tlsconfig                              | cipher_suites.go                 | `UpdateCipherSuites`, `GetCipherSuite`                                     |
| OCSP staple loading                         | pkg/tlsconfig                              | tls.go                           | `X509KeyPairWithOCSP`, `LoadX509KeyPairWithOCSP`                           |
| reloading `http.RoundTripper`               | pkg/tlsconfig                              | tlsconfig.go                     | `HTTPTransport`, `NewHTTPTransportWithReloader`                            |
| TLS listener / eager handshake              | pkg/transport                              | listener_tls.go                  | `NewTLSListener`                                                           |
| CRL / revocation check on client certs      | pkg/transport, pkg/crlcache                | listener_tls.go, crlcache.go     | `TLSInfo.CRLVerifier`, `Verifier`                                          |
| handshake failure callback                  | pkg/transport                              | tls.go                           | `TLSInfo.HandshakeFailure`                                                 |
| graceful shutdown / request timeout         | gserver, restserver                        | server.go                        | `Server.Close`, `HTTPServer.StopHTTP`, `WithShutdownTimeout`               |
| server lifecycle events                     | restserver                                 | server.go                        | `OnEvent`, `ServerEvent`                                                   |
| REST bind address helpers                    | restserver                                 | config.go                        | `GetPort`, `GetHostName`                                                   |
| REST server config access                    | restserver                                 | server.go                        | `HTTPServer.Config`, `HTTPConfig`                                          |
| custom middleware / interceptors            | gserver, restserver                        | options.go, server.go            | `WithMiddleware`, `WithUnaryServerInterceptor`, `WithMuxFactory`           |
| service registration (REST/gRPC)            | gserver, restserver                        | server.go, service.go            | `RouteRegistrator`, `GRPCRegistrator`, `ServiceFactory`, `Service`         |
| service registry / DI lookup                | pkg/discovery                              | discovery.go                     | `Discovery.Register/Find`                                                  |
| dig container for tests                     | tests/mockappcontainer                     | builder.go                       | `NewBuilder`                                                               |
| readiness gate                              | gserver, restserver, restserver/ready      | server.go, ready.go              | `IsReady`, `NewServiceStatusVerifier`                                      |
| slow request logging / gRPC metrics         | gserver                                    | logs.go                          | `WarnUnaryRequestLatency`, `logRequest`                                    |
| request logging (HTTP)                      | restserver/telemetry                       | requestlogger.go                 | `NewRequestLogger`                                                         |
| log skip paths                              | restserver/telemetry, gserver              | requestlogger.go, config.go      | `LoggerSkipPath`, `ShouldSkip`, `Config.SkipLogPaths`                      |
| HTTP request metrics                        | restserver/telemetry                       | request_metrics.go               | `NewRequestMetrics`                                                        |
| response status/size capture                | restserver/telemetry                       | response_capture.go              | `ResponseCapture`                                                          |
| metric descriptors                          | metricskey                                 | describe.go                      | `HTTPReqPerf`, `GRPCReqPerf`, `*ByRole`, `StatsVersion`, `HealthLogErrors` |
| metrics init (prometheus / cloudwatch)      | pkg/appinit                                | metrics.go                       | `Metrics`                                                                  |
| metrics config YAML                         | pkg/appinit/config                         | config.go                        | `Metrics`                                                                  |
| logging flags / log rotation                | pkg/appinit                                | init.go                          | `LogConfig`, `Logs`                                                        |
| CPU profiling                               | pkg/appinit                                | init.go                          | `CPUProfiler`                                                              |
| static response headers                     | gserver                                    | config.go                        | `Config.HTTPHeaders`, `Config.Validate`                                    |
| max message size (gRPC)                     | gserver, pkg/rpcclient                     | options.go, client.go            | `MaxRecvMsgSize`, `MaxSendMsgSize`, `defaultMaxCallSendMsgSize`            |
| max request size (REST, advisory)           | restserver                                 | server.go                        | `MaxRequestSize`                                                           |
| header copy / trailer prefix handling       | gserver                                    | header.go                        | `copyHeader`, `replaceInKeys`                                              |
| header name constants                       | xhttp/header                               | headers.go                       | `XCorrelationID`, `Authorization`, `Cookie`, `ProxyAuthorization`, ...      |
| correlation ID (HTTP)                       | xhttp/correlation                          | correlation.go                   | `NewHandler`, `ID`                                                         |
| correlation ID (gRPC)                       | xhttp/correlation                          | correlation.go                   | `NewAuthUnaryInterceptor`, `WithMetaFromContext`                           |
| correlation ID (client side)                | pkg/retriable                              | retriable.go                     | `convertRequest`                                                           |
| gRPC stream context override                | pkg/streamctx                              | streamctx.go                     | `WithContext`                                                              |
| structured API error                        | xhttp/httperror                            | errors.go                        | `Error`, `New`, `Wrap`                                                     |
| error → HTTP status                         | xhttp/httperror                            | errors.go                        | `Status`                                                                   |
| gRPC ↔ HTTP code mapping                    | xhttp/httperror                            | codes.go                         | `codeStatus`, `statusCode`, `HTTPStatusFromRPC`                            |
| multi-error (validation)                    | xhttp/httperror                            | many.go                          | `ManyError.Add`                                                            |
| gRPC error with correlation detail          | xhttp/httperror                            | rpc.go                           | `Error.GRPCStatus`, `CorrelationID`                                        |
| OAuth error mapping                         | xhttp/httperror                            | codes.go                         | `FromOAuth`                                                                |
| JSON response / error writing               | xhttp/marshal                              | marshal.go                       | `WriteJSON`                                                                |
| gzip responses                              | xhttp/marshal                              | marshal.go                       | `WriteJSON`                                                                |
| pretty print (`?pp`)                        | xhttp/marshal                              | json.go                          | `PrettyPrintSetting`                                                       |
| JSON body decoding (strict)                 | xhttp/marshal                              | json.go                          | `DecodeBody`, `DecoderHandle`                                              |
| caller identity                             | xhttp/identity                             | identity.go                      | `Identity`, `NewIdentity`, `AuthMethod`                                    |
| identity middleware (HTTP)                  | xhttp/identity                             | ctx.go                           | `NewContextHandler`                                                        |
| identity interceptor (gRPC)                 | xhttp/identity                             | ctx.go                           | `NewAuthUnaryInterceptor`, `NewStreamServerInterceptor`                    |
| request context (identity/IP/UA)            | xhttp/identity                             | ctx.go                           | `FromRequest`, `FromContext`                                               |
| `X-Forwarded-For` / `X-Real-Ip`             | xhttp/identity                             | realip.go                        | `ClientIPFromRequest`, `ClientIPFromGRPC`                                  |
| `X-Forwarded-Proto`                         | restserver, xhttp/identity                 | server.go, realip.go             | `GetServerURL`, `ForwardedProto`                                            |
| basic auth parsing                          | xhttp/identity                             | basicauth.go                     | `BasicAuthFromRequest`                                                     |
| test identity injection                     | xhttp/identity                             | identity.go                      | `WithTestIdentity`                                                         |
| identity provider / role mapping            | gserver/roles                              | roles.go                         | `New`, `IdentityProvider`                                                  |
| JWT role mapping                            | gserver/roles                              | roles.go, config.go              | `jwtIdentity`, `JWTIdentityMap`                                            |
| DPoP verification (server)                  | gserver/roles                              | roles.go                         | `dpopIdentity`                                                             |
| AWS STS caller identity (AWS4 token)        | gserver/roles                              | roles.go                         | `awsIdentity`, `ValidateSTSPresignedURL`, `ParseSTSTokenExpiration`        |
| TLS / SPIFFE role mapping                   | gserver/roles                              | roles.go                         | `tlsIdentity`, `GenericIdentityMap`                                        |
| `SkipAuthPaths`                             | gserver/roles                              | roles.go, config.go              | `IdentityFromRequest`, `IdentityMap.SkipAuthPaths`                         |
| cookie auth / CSRF double submit            | gserver/roles                              | roles.go                         | `enforceCSRFCookieAndHeader`, `CookiesConfig`                              |
| strict auth mode                            | gserver/roles                              | config.go                        | `IdentityMap.Strict`                                                       |
| guest role                                  | gserver/roles, xhttp/identity              | roles.go, identity.go            | `GuestRoleName`                                                            |
| path/role authorization                     | restserver/authz                           | authz.go                         | `Provider.Allow`, `AllowAny`, `AllowAnyRole`                               |
| authz YAML config                           | restserver/authz                           | authz.go                         | `Config`                                                                   |
| authz HTTP handler / gRPC interceptors      | restserver/authz                           | authz.go                         | `NewHandler`, `NewUnaryInterceptor`, `NewStreamServerInterceptor`          |
| role mapper                                 | restserver/authz                           | authz.go                         | `SetRoleMapper`, `SetGRPCRoleMapper`                                       |
| gRPC client credentials bundle              | gserver/credentials                        | credentials.go                   | `NewBundle`, `Bundle`                                                      |
| authorization metadata key                  | gserver/credentials                        | credentials.go                   | `TokenFieldNameGRPC`                                                       |
| token refresh / caller identity (client)    | gserver/credentials, pkg/retriable         | credentials.go, retriable.go     | `CallerIdentity`, `Token.Expired`, `WithCallerIdentity`                    |
| DPoP proof (client)                         | gserver/credentials, pkg/retriable         | credentials.go, retriable.go     | `Bundle.WithDPoP`, `Client.Do`                                              |
| OAuth fixed token                           | gserver/credentials                        | oauth.go                         | `NewOauthAccess`                                                           |
| gRPC client construction                    | pkg/rpcclient                              | client.go                        | `New`, `NewFromURL`                                                        |
| gRPC client TLS endpoint validation         | pkg/rpcclient                              | client.go                        | `New`, `Config.TLS`                                                        |
| gRPC blocking dial timeout                  | pkg/rpcclient                              | client.go                        | `Client.dial`, `Config.DialTimeout`                                        |
| retry policy / backoff                      | pkg/retriable                              | retriable.go                     | `Policy`, `DefaultPolicy`, `ShouldRetry`, `DefaultShouldRetryFactory`      |
| non-retriable errors (TLS/DNS)              | pkg/retriable                              | retriable.go                     | `DefaultNonRetriableErrors`                                                |
| request timeout (HTTP client)               | pkg/retriable                              | retriable.go                     | `Policy.RequestTimeout`, `WithTimeout`                                     |
| rewindable request body                     | pkg/retriable                              | request.go                       | `Request`, `NewRequest`                                                    |
| header propagation via context              | pkg/retriable                              | retriable.go                     | `WithHeaders`, `PropagateHeadersFromRequest`                               |
| `User-Agent` / `X-CLIENT-IP`                | pkg/retriable                              | retriable.go                     | `WithUserAgent`                                                            |
| Bearer token storage (`.auth_token`)        | pkg/retriable                              | storage.go                       | `Storage`, `SaveAuthToken`, `LoadAuthToken`                                |
| token from env var                          | pkg/retriable, pkg/rpcclient               | config.go                        | `CheckAuthTokenFromEnv`, `LoadAuthTokenOrFromEnv`                          |
| DPoP key files (`.jwk`)                     | pkg/retriable                              | storage.go                       | `Storage.SaveKey/LoadKey/ListKeys`, `KeyInfo`                              |
| nonce / `Replay-Nonce`                      | pkg/retriable                              | nonce.go                         | `NonceProvider`, `DefaultReplayNonceHeader`, `Client.WithNonce`            |
| custom DNS server                           | pkg/retriable                              | retriable.go                     | `WithDNSServer`                                                            |
| multi-client YAML config                    | pkg/retriable                              | config.go                        | `Config`, `LoadFactory`, `Factory`                                         |
| request dump (debug)                        | pkg/retriable                              | dumpreq.go                       | `DumpRequestOut`                                                           |
| Redis connection / TLS / auth               | pkg/redisclient                            | redisclient.go                   | `NewRedisClient`, `Config`                                                 |
| Redis key prefix                            | pkg/redisclient                            | redisclient.go                   | `WithPrefix`, `Key`, `SubKey`                                              |
| Redis value marshalling                     | pkg/redisclient                            | marshal.go                       | `Marshal`, `UnmarshalStringCmd`                                            |
| distributed lock                            | pkg/redisclient                            | redisclient.go                   | `TryLock`, `ReleaseLock`, `IsLocked`                                       |
| rate limit (Redis window)                   | pkg/redisclient                            | redisclient.go                   | `TryAcquireRateLimit`, `GetRateLimitRemainingTime`                         |
| bounded set / hash (eviction)               | pkg/redisclient                            | redisclient.go                   | `SAddWithEviction`, `HSetWithEviction`                                     |
| key scan                                    | pkg/redisclient                            | redisclient.go                   | `ScanKeys`, `Keys`                                                         |
| cache provider abstraction                  | pkg/cache                                  | cache.go                         | `Provider`                                                                 |
| cache TTL defaults                          | pkg/cache                                  | cache.go                         | `DefaultTTL`, `KeepTTL`                                                    |
| cache expiry / cleanup                      | pkg/cache                                  | memory.go                        | `CleanExpired`, `NowFunc`                                                  |
| read-through cache                          | pkg/cache                                  | cache.go                         | `GetOrSet`                                                                 |
| pub/sub (cache)                             | pkg/cache                                  | memory.go, redis.go              | `Publish`, `Subscribe`, `Subscription`                                     |
| cache namespacing                           | pkg/cache                                  | proxy.go                         | `NewProxyProvider`                                                         |
| not-found sentinel                          | pkg/cache, pkg/redisclient                 | cache.go, redisclient.go         | `ErrNotFound`, `IsNotFoundError`                                           |
| cron / periodic tasks                       | pkg/tasks                                  | scheduler.go                     | `NewScheduler`, `Scheduler`                                                |
| schedule string format                      | pkg/tasks                                  | task.go                          | `ParseSchedule`                                                            |
| task run lock / overlap prevention          | pkg/tasks                                  | task.go                          | `task.Run`, `WithRunTimeout`                                               |
| task status publishing                      | pkg/tasks                                  | scheduler.go                     | `Publisher`                                                                |
| test clock override                         | pkg/tasks, pkg/cache                       | task.go, cache.go                | `TimeNow`, `NowFunc`                                                       |
| free port for tests                         | tests/testutils                            | testutils.go                     | `CreateBindAddr`, `CreateURL`                                              |

## Packages

### github.com/effective-security/porto/gserver

Purpose: Combined gRPC + gRPC-Web + REST server. `Start` opens one cmux
listener per unique address, runs a gRPC server and an `http.Server` (REST
router) on each, translates gRPC-Web to gRPC on TLS listeners, and wires the
fixed middleware/interceptor chains.

Files:

- `doc.go` — package overview and usage example.
- `server.go` — `Server`/`GServer`, `Start`, service registry, `Close`, error channel.
- `serve.go` — `configureListeners` (URL schemes, TLS, keepalive), `serveCtx.serve` (cmux split), `configureHandlers` (HTTP chain), `corsHandler` (REST/preflight CORS response headers; an empty origin list allows none, and a disallowed actual request still reaches the handler), `configureRateLimiter`, `grpcServer` (interceptor chain), `grpcHandlerFunc` (gRPC / gRPC-Web / REST mux on TLS listeners), `NewRequestValidationUnaryInterceptor`, `panicInterceptor`.
- `grpc_web_response.go` — `grpcWebResponse`: `http.ResponseWriter` that rewrites gRPC responses into gRPC-Web framing (trailer frame, base64 for `-text`, pooled optional gzip for unary).
- `header.go` — `copyHeader` and option helpers used for gRPC → gRPC-Web header/trailer translation.
- `logs.go` — gRPC request logging/metrics interceptors.
- `config.go` — `Config` (`Config.Validate`), `TLSInfo`, `KeepAliveCfg`, `CORS` (`CORS.Validate`), `RateLimit`, `SwaggerCfg`.
- `options.go` — `WithMiddleware`, `WithUnaryServerInterceptor`, `WithStreamServerInterceptor`, `MaxRecvMsgSize`, `MaxSendMsgSize`.

Entry points:

- `Start(name, cfg, container, factories, opts...) (GServer, error)` — the only constructor; starts serving immediately.
- `GServer` — `AddService`, `Service`, `IsReady`, `Err`, `Close`, `Discovery`.
- `ServiceFactory`, `Service`, `RouteRegistrator`, `GRPCRegistrator`, `StartSubcriber` — plug-in contracts.
- `Config` YAML keys: `listen_urls`, `server_tls{cert,key,trusted_ca,client_ca,client_cert_auth,cipher_suites}`, `services`, `identity_map`, `authz`, `cors`, `rate_limit`, `trusted_proxy_cidrs`, `timeout.request`, `keep_alive{min_time,interval,timeout}`, `max_recv_msg_size`, `max_send_msg_size`, `http_headers`, `logger_skip_paths`, `prom_grpc`, `debug_logs`.

Invariants:

- `Start` returns errors, starting with the `Config.Validate` checks; `newServer` calls the unexported `Config.validate`, which also returns the parsed `TrustedProxyCIDRs` policy so it is parsed once. `configureHandlers` panics through the logger if the authz handler cannot be built. Handler panics are recovered into 500 / `codes.Internal` (unary only; the stream chain has no recovery).
- Process-global: package logger; `WarnUnaryRequestLatency`. The gRPC gzip compressor is registered by blank import.
- Every name in `Config.Services` must exist in the factory map; factories run through `dig.Container.Invoke`. The container must provide `discovery.Discovery` and, when JWT/DPoP is enabled, `jwt.Parser`.
- Listen URL schemes: `http`, `https`, `unix`, `unixs`; no scheme → https when TLS is configured. The same address listed twice yields one listener serving both secure and insecure.
- Plain listeners: cmux routes HTTP/2 → gRPC (h2c), HTTP/1 → REST; gRPC-Web and `HTTPHeaders` are only handled on TLS listeners, where everything goes through `http.Server` and `grpcHandlerFunc` selects by `Content-Type`.
- HTTP chain (outer → inner): trusted proxy policy → rate limit → correlation → CORS (if enabled) → identity → metrics → request logger → authz (if configured) → readiness → `WithMiddleware` → router. The default limiter keys on the client IP resolved by `NewTrustedProxyHandler`: tollbooth checks a shallow request copy whose `RemoteAddr` is that bare IP, so `X-Rate-Limit-Request-Remote-Addr` echoes the limiter key rather than the socket peer; the handler and `OnLimitReached` get the original request; a request without a client IP is not limited. Explicit `headers_ip_lookups` uses `tollbooth.LimitHandler` as is, overrides that policy, and must be used only when a proxy overwrites the chosen headers. Unary gRPC chain: panic recovery → validation → correlation → log → identity → authz (only when configured) → prometheus (opt) → custom. Stream chain: log → correlation → identity → authz (only when configured) → prometheus → custom.
- Headers read: `Content-Type`, `Origin`, `Accept-Encoding`, `X-GRPC-Stream`. For gRPC-Web, CORS headers are written only when `CORS.GetEnabled()` and an allowed `Origin` is present. Nonempty `AllowedOrigins` uses `rs/cors` matching, including its origin patterns; explicit `*` allows all origins and an empty list allows none. `Start` rejects an enabled `*` with `AllowCredentials` (`CORS.Validate`) and, while CORS is enabled, any `Access-Control-*` name in `HTTPHeaders` (`Config.Validate`, case-insensitive), so static headers cannot bypass the CORS policy; gRPC-Web never sends `Access-Control-Allow-Credentials` with `Access-Control-Allow-Origin: *`. A disallowed gRPC-Web POST gets HTTP 403; a disallowed preflight gets no allow-origin header. REST CORS is not request or CSRF protection: `rs/cors` still runs the handler for a disallowed actual request and only omits CORS response headers. `Access-Control-Expose-Headers` merges configured and service names with response and gRPC trailer names without case-insensitive duplicates; service response metadata cannot override server CORS policy headers. Reflected and denied origins add `Vary: Origin`; `prepareHeaders` merges service `Vary` header and trailer metadata without dropping it. Other headers written: `Content-Encoding: gzip`, `Config.HTTPHeaders`.
- gRPC-Web compression is enabled when `Accept-Encoding` contains `gzip` as a substring (q-values ignored, P-076) and `X-GRPC-Stream` is absent.
- Compressed gRPC-Web responses borrow a gzip writer from a pool; `Close` is idempotent because both `finishRequest` and the handler's deferred cleanup call it. Writers are reset before reuse and release the previous response writer on return to the pool. After `Close`, body writes to a compressed response return `errWriteAfterClose` and late trailer writes are logged and dropped, so raw bytes never follow the gzip footer.
- Close ordering: services `Close()` → `stopc` → per-listener `http.Shutdown` + `grpc.Stop`/`GracefulStop` within `Timeout.Request` (default 3s) → listeners closed. `Err()` is buffered and never closed. The TLS reloader is not closed (P-004).
- Keepalive: `MaxConnectionIdle` fixed at 5m; enforcement `MinTime` only if >0; `Time/Timeout` only if both >0.

Tests: `server_test.go` and `example_test.go` start real servers on random ports using `tests/mockappcontainer` and `tests/testutils.CreateURL`; TLS fixtures in `testdata/test-server{,-key,-rootca}.pem`; `grpc_web_test.go` and `grpc_web_bench_test.go` unit-test the gRPC-Web writer with `httptest.ResponseRecorder`; `serve_test.go` drives `grpcHandlerFunc` with a bare `grpc.NewServer()`.

### github.com/effective-security/porto/gserver/credentials

Purpose: gRPC credential helpers: a `grpccredentials.Bundle` (TLS transport plus per-RPC `authorization` metadata with static, refreshable or DPoP-signed tokens) and a fixed-token `PerRPCCredentials`.

Files:

- `doc.go` — overview and client example.
- `credentials.go` — `Config`, `Token`, `CallerIdentity`, `Bundle`, `NewBundle`, transport wrapper, `perRPCCredential`, `TimeISO8601`, `CacheTTL`, `TokenFieldNameGRPC`.
- `oauth.go` — `NewOauthAccess`.

Entry points: `NewBundle(Config) Bundle` (`TransportCredentials()`, `PerRPCCredentials()`, `UpdateAuthToken`, `WithCallerIdentity`, `WithDPoP`); `NewOauthAccess(token)`; `Token.Expired`.

Invariants:

- Process-global vars: `TokenFieldNameGRPC = "authorization"`, `CacheTTL = 5m` (also the AWS cache TTL in `roles`), package logger.
- Metadata written: `authorization: "<TokenType> <AccessToken>"` and `dpop: <proof>` when the type is `DPoP` and a signer is set.
- `RequireTransportSecurity()` is always true; `NewWithMode` returns `(nil, nil)` (P-015).
- Token refresh happens lazily inside `GetRequestMetadata` when `Expired()`; the token is guarded by `authTokenMu`, signer/provider fields are not (P-014).

Tests: `credentials_test.go`, no network.

### github.com/effective-security/porto/gserver/roles

Purpose: Authenticates HTTP and gRPC callers (AWS STS presigned tokens, DPoP JWT, bearer JWT via header or cookie, TLS client cert with SPIFFE SAN) and maps them to roles, producing `identity.Identity`.

Files:

- `doc.go` — overview, example, YAML layout of `identity_map`.
- `config.go` — `IdentityMap` (`debug_logs`, `strict`, `cookies{auth,csrf,domain}`, `skip_auth`, `tls`, `jwt`, `jwt_dpop`, `aws`), `GenericIdentityMap`, `JWTIdentityMap`, `AWSIdentityMap`, `CookiesConfig`.
- `roles.go` — `IdentityProvider`, `New`, `IdentityFromRequest` / `IdentityFromContext`, per-method verifiers (`awsIdentity`, `dpopIdentity`, `jwtIdentity`, `tlsIdentity`), `enforceCSRFCookieAndHeader`, `ValidateSTSPresignedURL`, `ParseSTSTokenExpiration`, `CallerIdentity`, role-name constants.

Entry points:

- `New(*IdentityMap, jwt.Parser) (IdentityProvider, error)` — errors if JWT/DPoP is enabled without a parser.
- `IdentityProvider.IdentityFromRequest` (HTTP) and `IdentityFromContext(ctx, uri)` (gRPC) — the mappers gserver passes to `identity.NewContextHandler` / `identity.NewAuthUnaryInterceptor`.
- Constants `GuestRoleName`, `TLSUserRoleName`, `JWTUserRoleName`, `DPoPUserRoleName`, `AWSUserRoleName`, `Default{Subject,Role,Tenant}Claim`.

Invariants:

- Never panics; returns errors only in `Strict` mode; otherwise falls through to the next method and finally to guest.
- Evaluation order: `SkipAuthPaths` (exact path, HTTP only) → `AWS4` → `DPoP` → `Bearer` header, else cookie `cookies.auth` with CSRF double-submit on unsafe methods (HTTP only) → TLS peer cert (first cert must carry exactly one `spiffe://` URI SAN). A scheme without a space is treated as `Bearer`.
- Headers/metadata read: `Authorization`, `DPoP`, `Cookie`, `X-CSRF-Token`; gRPC peer TLS state via `peer.FromContext`.
- Role lookup: reverse map `claim value → role` built once in `New` (last role wins); fallback `default_authenticated_role`. JWT claims default to `sub`/`email`/`tenant`. AWS subject form `"<account>:<type>/<name>"` or full ARN; `allowed_accounts` filter.
- AWS4 tokens are base64url presigned STS URLs. `ValidateSTSPresignedURL` requires `https`, no userinfo, an AWS STS host (global, regional, FIPS, China, or VPC endpoint under `amazonaws.com`) and `Action=GetCallerIdentity` before any request is made; the lookup uses a dedicated client with a 10s timeout and a 64 KiB body cap, and only the host is logged on failure. Successful lookups are cached in a 100-entry LRU keyed by URL for `credentials.CacheTTL`.
- DPoP proofs are verified against `https://<host><path>` for HTTP and `POST <uri>` for gRPC; a JWT with `cnf` is rejected on the bearer path.

Tests: `roles_test.go` (mock JWT parser, `createPeerContext`, `TestValidateSTSPresignedURL`), `csrf_test.go`, `internal_test.go`. No network.

### github.com/effective-security/porto/restserver

Purpose: HTTP/HTTPS REST server hosting `Service` implementations behind an httprouter mux with a fixed middleware chain.

Files:

- `server.go` — `HTTPServer` lifecycle (`New`/`StartHTTP`/`StopHTTP`), middleware assembly in `NewMux`, lifecycle events, `GetServerURL` helpers.
- `router.go` — `Router` interface over httprouter, `Params`, `Handle`, `CORSOptions` (rs/cors adapter including `wrapAllowOriginRequestFunc`).
- `config.go` — `Config` / `TLSInfoConfig` contracts, `GetPort`, `GetHostName`.
- `service.go` — `Service` interface.

Entry points:

- `New(version, ipaddr, Config, *tls.Config) (*HTTPServer, error)` — nil TLS means plain HTTP.
- `WithAuthz` / `WithIdentityProvider` / `WithTrustedProxies` / `WithCORS` / `WithShutdownTimeout` / `WithMuxFactory` — configure before `StartHTTP`; all but `WithMuxFactory` return the server for chaining.
- `AddService`, `StartHTTP`, `StopHTTP`, `NewMux`, `IsReady`, `OnEvent`; `Router` methods; `GetServerURL`, `GetServerBaseURL`.

Invariants:

- `StartHTTP` binds HTTP and HTTPS listeners synchronously and returns bind errors; serving remains asynchronous. A failed bind can be retried, but a successfully started instance cannot be restarted.
- `AddService` panics on duplicate names; `NewMux` panics if the authz handler cannot be built.
- Chain (outer → inner): trusted proxy policy → correlation → identity → metrics → request logger → authz (if set) → ready → CORS (if set) → router. `WithTrustedProxies` takes a policy from `identity.ParseTrustedProxies` (CIDR errors are returned there); nil trusts no proxy. `StartHTTP` applies the policy to custom mux factories too. Default identity mapper is `identity.GuestIdentityMapper`; logger granularity is `time.Millisecond`.
- `StopHTTP`: mark unready → wait for Started callbacks → broadcast Stopping → `Shutdown` with `shutdownTimeout` (default 5s) → `Service.Close()` for all → broadcast Stopped. Calls before start do nothing; concurrent and repeated calls wait for the first shutdown. A timeout still closes services after `Shutdown` returns. Lifecycle callbacks must not call `StopHTTP` synchronously.
- `serving` is an `atomic.Bool`; `IsReady` reads services under `lock.RLock`. `HTTPServer.Config()` and `HTTPConfig()` return the same configuration. Event handlers are copied under `lock.RLock` before callbacks run, so callbacks may register handlers.
- `GetPort` uses `net.SplitHostPort` for host:port and defaults bare IPv6 literals to port 443. `GetHostName` returns IPv6 hosts without brackets; `GetServerURL` and `GetServerBaseURL` rebuild host:port with `net.JoinHostPort`.
- `GetServerURL` accepts `X-Forwarded-Proto` only for a configured trusted peer and only when the value is `http` or `https`. 404 → JSON `not_found`. `MaxRequestSize` (64 MiB) is advisory only (P-026).

Tests: `rest_test.go` suite builds CA/server/client chains with `xpki/testca` in a temp dir; `server_test.go` uses random ports via `tests/testutils`; `router_test.go` CORS; `example_test.go` uses `testdata/test-server*.pem`.

### github.com/effective-security/porto/restserver/authz

Purpose: path-segment/role access control tree for HTTP handlers and gRPC interceptors, configurable from YAML/JSON.

Files: `authz.go` — `Config`, `Provider` (tree build/walk/clone, `NewHandler`, interceptors, access logging); `doc.go`.

Entry points: `New(*Config)` parsing `allow` entries `"/path:role1,role2"`; `Allow`, `AllowAny`, `AllowAnyRole`, `SetRoleMapper`, `SetGRPCRoleMapper`, `Clone`; `NewHandler(delegate)`, `NewUnaryInterceptor()`, `NewStreamServerInterceptor()`; interfaces `HTTPAuthz`, `GRPCAuthz`.

Invariants:

- Paths must start with `/` or `walkPath` panics; match is by whole segment on the deepest configured node; `AllowAny` beats roles; `guest` and empty roles are never allowed by `Allow`/`AllowAnyRole`.
- `NewHandler` snapshots through `Clone`; interceptors use the live provider. An empty tree denies everything.
- HTTP `OPTIONS` is always allowed (P-033). Denial is `httperror.Unauthorized` (401 / `codes.PermissionDenied`, P-027).
- Mutators are unsynchronized: configure before serving.
- Config tags: `allow`, `allow_any`, `allow_any_role`, `log_allowed_any`, `log_allowed`, `log_denied`, `log_level`, `logger_skip_paths[{path,agent}]`.

Tests: `authz_test.go` — tree walk, YAML load, handler and interceptor allow/deny with `identity.WithTestIdentity`.

### github.com/effective-security/porto/restserver/ready

Purpose: readiness gate middleware returning JSON 503 `not_ready` until `ServiceStatus.IsReady()` is true.

Files: `ready.go` — `ServiceStatus`, `NewServiceStatusVerifier`.

Invariants: `IsReady` is called on every request and must be cheap and thread-safe. The package-level `errUnavailable` is shared and mutated by `WriteHTTPResponse` (P-016).

### github.com/effective-security/porto/restserver/telemetry

Purpose: request logging and request metrics middleware plus the `ResponseCapture` writer.

Files: `requestlogger.go` (`RequestLogger`, `NewRequestLogger`, `LoggerSkipPath`, `ShouldSkip`, `WithLoggerSkipPaths`), `request_metrics.go` (`NewRequestMetrics`), `response_capture.go` (`ResponseCapture`).

Invariants:

- `NewRequestLogger` panics on a nil handler; a nil logger returns the handler unwrapped; granularity must be > 0 (P-031).
- Log fields: method, path, status, bytes, duration, remote (`identity.ClientIPFromRequest`, the IP cached by `identity.NewTrustedProxyHandler` when present), agent; INFO via `ContextKV`.
- Metric tags: verb, status, uri (raw path, P-023), role; 404 collapses to `unknown`.
- `LoggerSkipPath` tags `path`, `agent`; `*` wildcard; agent is a substring match.
- `ResponseCapture` has no `Hijacker`/`Unwrap` (P-024).

### github.com/effective-security/porto/xhttp/correlation

Purpose: correlation/request ID propagation across HTTP, gRPC metadata, contexts and logs.

Files: `correlation.go`.

Entry points: `NewHandler(delegate)`, `NewAuthUnaryInterceptor()`, `NewStreamServerInterceptor()`, `ID(ctx)`, `Value(ctx)`, `WithID(ctx)`, `WithMetaFromContext(ctx)`, `WithMetaFromRequest(r)`, `NewFromContext(ctx)`, `Correlator`, `IDSize`, `CorrelationIDgRPCHeaderName`.

Invariants:

- Incoming ID sources (HTTP): `X-Correlation-ID`, then `X-Request-ID`; (gRPC) `x-correlation-id`, `x-request-id`; truncated to 12 chars; otherwise random.
- Writes the response header `X-Correlation-ID` and the xlog KV `ctx`.
- `WithMetaFromRequest` copies `x-*`, `grpc-*`, `authorization`, `date`, `timestamp` headers into incoming and outgoing MD (forwards credentials).
- gRPC metadata keys are lowercase; `WithMetaFromRequest` forwards the resolved (possibly truncated) correlation ID under `CorrelationIDgRPCHeaderName` and gives any `x-request-id` alias the same value.
- `NewFromContext` detaches from cancellation. gRPC interceptors recover panics into `codes.Unknown`.

### github.com/effective-security/porto/xhttp/header

Purpose: constants for HTTP header names and content-type values, including `Vary` for response negotiation and `XForwardedFor`, `XRealIP`, `XForwardedProto` for proxy headers. No imports.

### github.com/effective-security/porto/xhttp/httperror

Purpose: structured API errors with HTTP status, code, gRPC status and correlation ID; JSON writer; HTTP ↔ gRPC code mapping; classification helpers.

Files: `errors.go` (`Error`, constructors, `Wrap`/`WrapWithCtx`, `Is*`, `Status`, `WriteHTTPResponse`), `codes.go` (`Code*`, `httpCode`, `codeStatus`, `statusCode`, `HTTPStatusFromRPC`, `FromOAuth`), `many.go` (`ManyError`), `rpc.go` (`NewGrpc`, `NewGrpcFromCtx`, `NewFromPb`, `GRPCStatus`, `CorrelationID`), `encoder.go`.

Invariants:

- Wire JSON `{code, message, request_id?}`; `ManyError` adds `errors{}`.
- `WithContext`/`WithCause`/`WriteHTTPResponse` mutate the receiver; do not share `Error` values across requests.
- Mapping: `PermissionDenied` and `Unauthenticated` → 401 (P-027); `Canceled`/`DeadlineExceeded` → 408; `CodeTimeout` → `DeadlineExceeded`; unknown codes → RPCStatus 0.
- `Wrap` classification is substring-based ("invalid"/"bad"/"400" → 400; "not found"/"404" → 404; "timeout"/"deadline"/"cancel" → 408).
- `Is` compares Code and Message; `Unwrap` skips one wrapper level of the cause.

### github.com/effective-security/porto/xhttp/identity

Purpose: caller identity (role/subject/tenant/claims/auth method) and connection facts (client IP, UA, target) in request contexts for HTTP and gRPC.

Files: `identity.go` (`Identity`, `NewIdentity`, `AuthMethod`, guest mappers, `WithTestIdentity`), `ctx.go` (`RequestContext`, `FromContext/FromRequest/AddToContext`, `NewContextHandler`, `NewAuthUnaryInterceptor`/`NewStreamServerInterceptor`), `realip.go` (`TrustedProxies`, `ParseTrustedProxies`, `WithTrustedProxies`, `NewTrustedProxyHandler`, `ClientIPFromRequest`, `ClientIPFromGRPC`, `ForwardedProto`), `basicauth.go`.

Invariants:

- Never returns a nil identity: guest (`GuestRoleName = "guest"`, `MethodNone`) when missing. Mapper error → HTTP 401 JSON / gRPC `PermissionDenied`.
- An existing `RequestContext` in ctx is respected (test injection). `FromRequest` mutates the stored context in place.
- Without a trusted proxy policy, client IP is the socket peer and forwarded headers are ignored. `ParseTrustedProxies` validates CIDRs; `WithTrustedProxies` stores the immutable policy in context (replacing any policy and cached IP); `NewTrustedProxyHandler` applies it to HTTP and resolves the client IP once per request. The context value (`forwarding`) holds the policy plus the resolved IP and the `RemoteAddr` it was resolved for; `ClientIPFromRequest` returns the cached IP when `RemoteAddr` still matches, so header changes after the trust boundary are ignored and a request copy with another peer is resolved again. A request with an empty `RemoteAddr` has no client IP and returns "" (the pre-B05 fallback to `netutil.GetLocalIP` was removed). For trusted peers, XFF is walked right to left to the first untrusted address, including private addresses, or to the leftmost entry when every hop is trusted; malformed values fall back to the peer. IPv4-mapped IPv6 addresses are returned as IPv4. IPv6 zones (`fe80::1%eth0`) are ignored when matching trusted CIDRs, because `netip.Prefix.Contains` rejects zoned addresses; returned addresses keep their zone. `X-Real-Ip` is used only when XFF is absent. gRPC metadata follows the same rules. Proxies must overwrite client supplied forwarding headers. `ForwardedProto` accepts only `http` or `https` from a trusted peer.
- Unary gRPC interceptor recovers panics; the stream one does not. Only the first `trusted` argument of the gRPC interceptors is used; nil keeps a policy already in the context.

### github.com/effective-security/porto/xhttp/marshal

Purpose: JSON response writing (with errors, gzip, pretty-print) and strict JSON request decoding via ugorji codec.

Files: `marshal.go` (`WriteJSON`, `WritePlainJSON`, `WriteHTTPResponse`, `NewRequest`), `json.go` (`PrettyPrintSetting`, `NewEncoder`, `EncodeBytes`, `DecodeBytes`, `Decode`, `DecodeBody`, `DecoderHandle`).

Invariants:

- First non-nil body wins; `WriteHTTPResponse` implementers write themselves; other errors → 500 `unexpected` with `err.Error()` as message (P-032); non-404 errors are logged.
- Success: 200, `application/json`, gzip for payloads of at least 1 KiB when `Accept-Encoding` allows gzip with positive quality (a missing `q` means 1, a malformed or out-of-range `q` means 0; explicit gzip denial overrides `*`), pretty when `?pp`. `Vary: Accept-Encoding` is merged with existing values; gzip writers are pooled. `r` must be non-nil.
- Decoding is strict (`ErrorIfNoField`), maps → `map[string]any`, no size limit (P-026).
- Encoder handles are package globals initialised in `init`.

Tests: `marshal_test.go` covers negotiation, the compression threshold, `Vary`, decompressed payloads, and log line numbers derived from `runtime.Caller`; `marshal_bench_test.go` measures compressed responses.

### github.com/effective-security/porto/pkg/retriable

Purpose: HTTP client with retry policy, JSON marshalling, context header propagation, Bearer/DPoP authorization, replay nonces and file-based token/key storage. See also `pkg/retriable/README.md`.

Files: `doc.go`, `retriable.go` (`Client`, options, `Policy`, `Request`/`Do`, `DecodeResponse`, context header helpers), `client.go` (`Head/Get/Post/Put/Delete`), `config.go` (`Config`/`ClientConfig`/`RequestPolicy`/`TLSInfo`, `Factory`, `LoadClient`, `SetAuthorization`, `HostFolderName`), `storage.go` (`Storage`, `AuthToken`, `ParseAuthToken`, `KeyInfo`), `nonce.go` (`NonceProvider`), `request.go` (`Request`, `Requestor`), `dumpreq.go` (`DumpRequestOut`).

Entry points: `New(cfg, opts...)`, `Default(host)`, `LoadClient(file)`, `NewFactory`/`LoadFactory` → `CreateClient`/`ForHost`; `Client.Request/RequestURL/HeadTo`, `Get/Post/Put/Delete/Head`, `Do`; `SetAuthorization()`; `Policy`, `DefaultPolicy()`; `WithHeaders(ctx, map)`, `PropagateHeadersFromRequest`; `Storage.*`.

Invariants:

- Errors, not panics, except unchecked `*http.Transport` assertions in `WithTLS`/`WithDNSServer` (P-061).
- DEBUG request dumps redact `Authorization`, `DPoP`, `Cookie`, and `Proxy-Authorization` without mutating the request; `Client.Do` omits request bodies from its DEBUG dump.
- Client setters lock mutable fields; `Do` snapshots headers, policy, name, signer, and the HTTP client. Caller-identity refresh is shared by concurrent requests, with context-aware waiting and a fast path for valid tokens or no provider; changing the provider invalidates an in-flight refresh. Direct mutation of exported `Name`, `Policy`, `Config`, or the returned `HTTPClient()` still requires caller synchronization; configure transports before concurrent use (P-061).
- `ShouldRetry` order: ctx done → `TotalRetryLimit` → `NonRetriableErrors` → `Retries[0]`; status < 400 succeeds; 404/429 stop; other 4xx stop; 5xx → `Retries[status]`. `DefaultPolicy`: connection errors 3x/2s, 502/503 5x/1s, total 5, no timeout. A `request:` config block replaces the defaults with its own values (P-046).
- `RequestTimeout` applies to `Request` and helpers, not `Do`; its cancel func is intentionally not called (P-057).
- Headers written: `X-Correlation-ID`, `Authorization`, `DPoP`, `User-Agent`, `X-CLIENT-HOSTNAME`, `X-CLIENT-IP`; context headers override client headers.
- Authorization only for `https://` / `unixs://` hosts; token formats: opaque or `access_token=&exp=&dpop_jkt=&token_type=`.
- DPoP proofs are signed separately for each retry attempt; a DPoP authorization header without a configured signer returns an error.
- Config YAML: `host, tls{cert,key,trusted_ca}, request{retry_limit,timeout}, storage_folder`; `~` and `$VAR` are expanded; `LoadFactory` appends `HostFolderName(host)` to `storage_folder`.
- Storage files: `.auth_token` and `<thumbprint>.jwk` are written through mode-0600 temporary files and atomically replace existing files or symlinks. A newly created credentials folder uses mode 0700; existing directory permissions stay intact. An empty `StorageFolder` uses the working directory without changing its mode. A public-only DPoP key is rejected by `SetAuthorization`.

Tests: `retriable_test.go` (httptest servers; `TestMain` writes a test CA/client cert under `$TMPDIR/test-retriable`), `safety_test.go` (credential redaction, concurrent refresh, retry signing, storage permissions), `config_test.go` with `testdata/*.yaml`, `nonce_test.go`, `internal_test.go` (needs outbound DNS to 8.8.8.8).

### github.com/effective-security/porto/pkg/rpcclient

Purpose: build a `*grpc.ClientConn` plus default call options from a `Config` (TLS bundle, Bearer/DPoP per-RPC credentials, keepalive, message limits, optional blocking dial).

Files: `doc.go`, `client.go` (`Client`, `New`/`NewFromURL`, `newClient`, `dial`), `config.go` (`Config`, token loading, `Storage`).

Invariants:

- HTTP(S) scheme prefixes are stripped and `:443` is appended when no host port is given. `unixs:///path` is converted to gRPC's `unix:///path` resolver target; `unix:///path` is preserved.
- When `cfg.TLS != nil`, the endpoint must start with `https://` or `unixs://`; `New` otherwise returns an error. A nil TLS config uses `insecure.NewCredentials()`.
- Defaults: `WaitForReady(true)`, send limit 10 MiB, recv limit `math.MaxInt32`; `Config.CallOptions` replaces them.
- `DialTimeout > 0` waits for `connectivity.Ready`; otherwise lazy. Uses `grpc.NewClient`.
- `Config` has no yaml/json tags.

### github.com/effective-security/porto/pkg/redisclient

Purpose: prefixed, JSON-marshalling wrapper over go-redis v9 with helpers for lists/sets/hashes/zsets, bounded collections, a simple distributed lock and a per-window rate limiter.

Files: `doc.go`, `redisclient.go` (`Config`, `Provider`/`DistributedLock`/`RateLimiter`, `RedisClient`), `marshal.go`.

Entry points: `New(*Config)` (root client owning the connection), `NewWithClient`, `NewRedisClient`; `WithPrefix`, `Key`, `SubKey`; `Get/Set/Del`, `L*`, `S*`, `SAddWithEviction`, `H*`, `HSetWithEviction`, `Z*`, `ScanKeys`/`Keys`; `TryLock/ReleaseLock/IsLocked` (`lock:<key>`), `TryAcquireRateLimit/GetRateLimitRemainingTime`.

Invariants:

- `ErrNotFound` only from `Get`/`HGet`; `IsNotFoundError` also matches any "not found" message.
- Prefix is `/<trimmed>/`; keys built with `path.Join` (cleans `..`, P-044); prefixes do not nest.
- Only the root client's `Close` closes the connection and nils the embedded client (P-062).
- Config YAML: `server, ttl, client_tls{cert,key,trusted_ca}, user, password`; `password` overrides URL credentials; the server URL is logged at INFO (P-045).
- Eviction helpers, lock and rate limiter are multi-command and non-transactional (P-043, P-047, P-063).
- `Keys` uses `KEYS` (tests only); `ScanKeys` batches of 100, default limit 1000.

Tests: testcontainers `redis:8.2` with password `redis`; needs Docker.

### github.com/effective-security/porto/pkg/cache

Purpose: `Provider` cache abstraction (Set/Get with TTL, Delete, Keys, pub/sub) with memory, Redis and prefixing proxy backends.

Files: `doc.go`, `cache.go` (`Provider`, `Subscription`, `Config`, `RedisConfig`, `DefaultTTL`, `KeepTTL`, `NowFunc`, `GetOrSet`, `ErrNotFound`), `memory.go`, `redis.go`, `proxy.go`.

Invariants:

- Errors, not panics; `Get` requires a non-nil pointer; misses are `ErrNotFound`.
- TTL 0 → `DefaultTTL` (memory, 30m, package var) or `RedisConfig.TTL` (default 1h); `KeepTTL` (-1) → no expiry.
- Memory provider is unbounded; expiry enforced on `Get` and `CleanExpired`; `NowFunc` is process-global.
- Keys via `path.Join(prefix, key)`; Redis `Keys` strips the prefix, memory does not (P-064).
- `GetOrSet` writes a successful getter result with TTL 0 (the provider default), storing the dereferenced value so Redis string/byte reads remain compatible; a failed write leaves the destination unchanged and returns an error. Cache misses require a pointer to a concrete destination type because interface values do not round-trip reliably across providers. Concurrent misses may call the getter more than once. Pub/sub channels are not prefixed; memory `Publish` blocks on a full 10-slot subscriber buffer (P-042); Redis `ReceiveMessage` spawns a goroutine per receive (P-041).
- Subscription IDs use the Go 1.27 standard `uuid` package.
- Config YAML: `provider: redis|memory`, `redis{...}`; no factory reads `provider`.

Tests: `cache_test.go` runs the same matrix against redis (testcontainers), memory and proxy(memory), including read-through persistence; `get_or_set_test.go` covers default TTL, hit reuse, type errors, and write failures; `memory_test.go` covers `CleanExpired`.

### github.com/effective-security/porto/pkg/tasks

Purpose: in-process cron-like scheduler; runs functions on interval/daily/weekly schedules parsed from a human-friendly string.

Files: `doc.go`, `task.go` (`Task`, `Schedule`, `ParseSchedule`, run/next-run logic), `scheduler.go` (`Scheduler`, `Publisher`, options).

Entry points: `NewScheduler(opts...)` with `Add/Start/Stop`; `NewTask(format)`, `NewTaskAtIntervals`, `NewTaskDaily`, `NewTaskOnWeekday`, `New(*Schedule)`; bind with `Task.Do(name, fn, args...)`; `ParseSchedule` ("every N unit [hh:mm]", "<weekday> [hh:mm]", "hh:mm"); `Publisher`.

Invariants:

- Panics: `NewTaskDaily/NewTaskOnWeekday` on a bad hh:mm, `Task.Do` on a non-func or wrong arity. Errors: `NewTask/ParseSchedule/UpdateSchedule`, `Start` (already running); `Stop` succeeds when already stopped.
- Globals: `TimeNow`, location via `SetGlobalLocation`, package logger.
- `Start` spawns one ticker goroutine; each due task runs in its own goroutine with a per-task run lock and `WithRunTimeout` (default 1s); callback panics are recovered and logged. Tick = `WithTickerInterval` or min(1s, shortest Duration/10). Runnable tasks are sorted by a snapshot of next-run times using `slices.SortFunc`.
- `scheduler.lock` guards membership and lifecycle; `Task` has a separate RWMutex for callback, publisher, and run state. `List` copies the task slice; `Task.Schedule` deep-copies `LastRunAt` and returns a snapshot. `New(*Schedule)` copies its input. Use `Add/Clear` and `SetNextRun/UpdateSchedule` to mutate state. Custom `Task` implementations must provide their own concurrency safety.
- `Stop` closes the current run's quit channel under the lifecycle lock, is idempotent, and does not wait for task callbacks. `Start` may restart after `Stop`. Publisher callbacks run outside scheduler and task locks.
- Task ID: `WithID` or `uuid.NewV7()`.

Tests: time-based (`task_test.go`, `scheduler_test.go`) and overlapping reads, writes, stops, and callbacks (`concurrency_test.go`); `task_bench_test.go` measures `Run`; package race tests pass.

### github.com/effective-security/porto/pkg/tlsconfig

Purpose: build `tls.Config` from PEM files and keep the keypair fresh via a polling reloader; reloading RoundTripper and cipher-suite name mapping.

Files: `doc.go`, `tlsconfig.go` (`NewServerTLSFromFiles`, `NewClientTLSFromFiles`, `NewClientTLSWithReloader`, `HTTPTransport`), `tls.go` (`X509KeyPairWithOCSP`, `LoadX509KeyPairWithOCSP`), `reloader.go` (`KeypairReloader`), `cipher_suites.go` (`UpdateCipherSuites`).

Invariants:

- Defaults: MinVersion TLS 1.2, NextProtos h2 + http/1.1; `rootsFile` is used for both `RootCAs` and `ClientCAs` on the server; CA files with no valid certificates return an error.
- Expired certificates fail initial load or reload; a failed reload keeps the previous pair. If the current pair later expires, TLS callbacks return errors and `Keypair` returns nil. Expiry within one hour is logged as a warning.
- One poll goroutine per reloader (mtime polling plus an hourly forced reload); handlers run in their own goroutines; the goroutine snapshots timestamps under `RLock`; `Close` waits for an active reload, then closes `stopChan`. A second `Close` or `Reload` after `Close` returns an error; the poll goroutine does not log that closed error (`errReloaderClosed`).
- `Reload` marks itself in progress under the write lock, sleeps and loads outside the lock, then swaps the pair under the lock. A `Reload` that finds another in progress waits on `reloadDone`, then loads again, so a nil return means the files were read after the call started. File mtimes are stat'ed before each load attempt, so a write during the load triggers the next poll; `count` is atomic.
- `HTTPTransport` clones a supplied `http.Transport`, installs a fixed `TLSClientConfig` with `GetClientCertificate`, and closes idle connections on reload and `Close`. `RoundTrip` never mutates the active TLS config.
- `pkg/transport.TLSInfo.ServerTLSWithReloader` clears the static `Certificates` slice after installing `GetCertificate` so clients without SNI still receive the current, expiry-checked pair.
- OCSP staple file: `<certfile-minus-ext>.ocsp`; ignored if expired or unparsable, error if revoked.
- Test hook: package var `makeTicker`.

Tests: generate certs with `xpki/testca`; reloader tests rewrite files on a 100ms poll, and `b02_test.go` covers expiry, lock availability, Close versus Reload, Reload waiting for an active reload, concurrent reloads, no error log for a poll during Close (non-parallel: replaces `makeTicker` and the xlog formatter), stable transport config, and invalid CA bundles; `tls_test.go` has inline PEM fixtures.

### github.com/effective-security/porto/pkg/transport

Purpose: server-side listeners: eager-handshake TLS listener with CRL check, and TCP keepalive listeners; `TLSInfo` config → `tls.Config` with reloader.

Files: `doc.go`, `transport.go` (logger), `tls.go` (`TLSInfo`: `ServerTLSWithReloader`, `Config`, `Close`), `listener_tls.go` (`NewTLSListener`), `keepalive_listener.go` (`NewKeepAliveListener`).

Invariants:

- `TLSInfo` uses only `CertFile/KeyFile/TrustedCAFile/ClientCAFile/ClientAuthType/CipherSuites/CRLVerifier/HandshakeFailure`; the other fields are documented as unenforced (P-052).
- CRL check only sees `VerifiedChains` (needs ClientAuth ≥ `VerifyClientCertIfGiven`); Revoked → reject; verify error or Unknown → log and allow (fail-open).
- No handshake deadline (P-054); `Accept` errors on keepalive listeners are stack-wrapped (P-053); keepalive `Accept` panics for non-TCP conns.
- Reloader interval is 5 minutes; `TLSInfo.Close` stops it.
- `ServerTLSWithReloader` clears static certificates after installing `GetCertificate`, so handshakes without SNI use the current pair and receive expiry errors.

Tests: `tls_test.go` `init()` builds a CA/intermediate/server chain with `xpki/testca` under `os.TempDir()/test-transport` and verifies a handshake without SNI uses the callback; listener tests start `restserver` over the listener with a fake verifier.

### github.com/effective-security/porto/pkg/appinit and pkg/appinit/config

Purpose: service bootstrap: logging setup, metrics pipeline (Prometheus/CloudWatch), CPU profiler; `config.Metrics` is the YAML/JSON struct.

Files: `init.go` (`LogConfig`, `Flags`, `Logs`, `CPUProfiler`), `metrics.go` (`Metrics`, `contextCloser`), `cpu_profiler.go`; `config/config.go` (`Metrics`, `Prometheus`, `CloudWatch`).

Invariants:

- Process-global side effects: `xlog.SetFormatter` (or the logrotate formatter installed by `logrotate.Initialize`, which `Logs` keeps and only adjusts), `metrics.NewGlobal`, default Prometheus registry, `xlog.OnError` hook, package vars `promSink`/`cwSink` (once per process).
- `provider` is comma-separated: `prometheus | cloudwatch | inmem`; empty or disabled → `(nil, nil)`. A provider without its config block is an error. Prometheus HTTP endpoint runs in a goroutine with `logger.Fatal` on error (P-055). Reads env `NODE_NAME` for the `node` tag.
- Nil closers are normal; callers must nil-check.
- `LogDir` `/dev/null` discards; set → logrotate (10 MB / 10 days, buffered) with stderr as an extra sink when `LogStd`.
- Config keys: `disabled, provider, prefix, prefix_for_number_labels, prometheus{addr,expiration}, runtime_metrics, cloudwatch{aws_region,namespace,publish_interval,add_tags,replace_tags,with_sample_count}, global_tags, allowed_prefixes, blocked_prefixes`; `add_tags`/`replace_tags` are unused and `AwsEndpoint` is untagged (P-073).

Tests: `init_test.go` (log branches with `t.TempDir`, asserts the rotating file receives output), `cpu_profiles_test.go`. No `Metrics` tests.

### github.com/effective-security/porto/pkg/discovery

Purpose: tiny in-process service registry resolved by interface type (gserver exposes services to handlers through it).

Entry points: `New()`, `Register(server, svc)`, `Find(server, *iface)`, `ForEach(*iface, fn)`.

Invariants: key `<server>/<concrete type>`; duplicate or nil `Register` → error; `Find` requires a non-nil pointer-to-interface, server `""` means any; map iteration order makes multiple matches arbitrary. An RWMutex protects registration and lookup; `ForEach` snapshots matching entries before invoking callbacks so callbacks may register services. The caller owns synchronization of the destination interface value.

### github.com/effective-security/porto/pkg/crlcache

Purpose: `Verifier{Update() error; Verify(crt, issuer) (int, error)}` returning `ocsp.Good/Revoked/Unknown`, consumed by `transport.TLSInfo`. No implementation here; implementations must be concurrency-safe.

### github.com/effective-security/porto/pkg/streamctx

Purpose: wrap `grpc.ServerStream` to override `Context()` in stream interceptors. If `ss` is already a wrapper its context is replaced in place and the same object returned.

### github.com/effective-security/porto/metricskey

Purpose: `metrics.Describe` descriptors: `HTTPReqPerf`, `HTTPReqByRole`, `GRPCReqPerf`, `GRPCReqByRole`, `StatsVersion`, `HealthLogErrors`; `Metrics` slice. Names `http_requests_perf`, `http_requests_role`, `rpc_requests_perf`, `rpc_requests_role`, `version`, `log_errors`.

### github.com/effective-security/porto/tests/testutils and tests/mockappcontainer

Purpose: test helpers. `testutils`: `CreateURL`, `CreateBindAddr` (panic if no free port; TOCTOU), `JSON`, `CompareJSON`. `mockappcontainer`: `NewBuilder().WithConfig(*gserver.Config).WithJwtSigner(...).WithJwtParser(...).WithDiscovery(...).Container()` builds a `dig.Container`; `dig.Provide` errors are discarded.

## Build, test and CI

- `go.mod` targets Go 1.27; the standard `uuid` package is used.
- `make lint` = gofmt with rewrites, `go vet`, `govulncheck`, `golangci-lint` (revive `exported` + staticcheck `all`, comment presets excluded).
- `make test` needs Docker for `pkg/redisclient` and `pkg/cache`; `pkg/retriable` `internal_test.go` needs outbound DNS.
- `make covtest` writes `coverage.out`; CI (`.github/workflows/unittest.yml`) runs `make build covtest` and requires 90% total coverage. CI does not run `make lint` or `-race`.
- `make docs` regenerates `Documentation/api/*.md` with gomarkdoc (one file per non-test package).
- `pkg/tasks` and the other packages pass `go test -race`.
