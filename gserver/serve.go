package gserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth/v7/limiter"
	"github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/pkg/transport"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/restserver/ready"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/xlog"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/rs/cors"
	"github.com/soheilhy/cmux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
)

type serveCtx struct {
	listener net.Listener
	addr     string
	network  string
	secure   bool
	insecure bool

	ctx    context.Context
	cancel context.CancelFunc

	tlsInfo *transport.TLSInfo

	cfg *Config

	gopts []grpc.ServerOption
	// serversC carries the servers serve started; Close ranges over it, so it
	// must always be closed (see closeServers).
	serversC    chan *servers
	serversOnce sync.Once
}

// closeServers closes serversC exactly once. serve calls it after publishing
// its servers, its deferred cleanup calls it when serve fails before that,
// and Server.abort calls it when serve never runs, so Close never waits on a
// channel nobody will close.
func (sctx *serveCtx) closeServers() {
	sctx.serversOnce.Do(func() { close(sctx.serversC) })
}

type servers struct {
	secure bool
	grpc   *grpc.Server
	http   *http.Server
}

// configureListeners parses cfg.ListenURLs, builds the shared server TLS
// config (which starts its certificate reloader) when cfg.ServerTLS is set,
// and opens one listener per unique address. On error every listener opened
// so far is closed and the reloader is stopped. The caller owns the returned
// TLSInfo and must Close it.
func configureListeners(cfg *Config) (_ map[string]*serveCtx, _ *transport.TLSInfo, err error) {
	urls, err := cfg.ParseListenURLs()
	if err != nil {
		return nil, nil, err
	}

	// The cleanup reads these locals: the results are nil on every error return.
	var tlsInfo *transport.TLSInfo
	sctxs := make(map[string]*serveCtx)
	defer func() {
		if err == nil {
			return
		}
		for _, sctx := range sctxs {
			if sctx.listener != nil {
				logger.KV(xlog.INFO,
					"reason", "error",
					"network", sctx.network,
					"address", sctx.addr,
					"err", err)
				sctx.listener.Close()
			}
		}
		if tlsInfo != nil {
			tlsInfo.Close()
		}
	}()

	if !cfg.ServerTLS.Empty() {
		from := cfg.ServerTLS
		clientauthType := tls.VerifyClientCertIfGiven
		if from.GetClientCertAuth() {
			clientauthType = tls.RequireAndVerifyClientCert
		}
		tlsInfo = &transport.TLSInfo{
			CertFile:         from.CertFile,
			KeyFile:          from.KeyFile,
			TrustedCAFile:    from.TrustedCAFile,
			ClientCAFile:     from.ClientCAFile,
			ClientAuthType:   clientauthType,
			CipherSuites:     from.CipherSuites,
			HandshakeTimeout: cfg.Timeouts.Handshake,
			// CRLVerifier : TODO
		}

		if _, err = tlsInfo.ServerTLSWithReloader(); err != nil {
			return nil, nil, err
		}
	}

	gopts := []grpc.ServerOption{}
	if cfg.KeepAlive.MinTime > 0 {
		gopts = append(gopts, grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             cfg.KeepAlive.MinTime,
			PermitWithoutStream: false,
		}))
	}

	ka := keepalive.ServerParameters{
		MaxConnectionIdle: 5 * time.Minute,
	}
	if cfg.KeepAlive.Interval > 0 &&
		cfg.KeepAlive.Timeout > 0 {
		ka.Time = cfg.KeepAlive.Interval
		ka.Timeout = cfg.KeepAlive.Timeout
	}
	gopts = append(gopts, grpc.KeepaliveParams(ka))

	for _, u := range urls {
		if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "unix" && u.Scheme != "unixs" {
			return nil, nil, errors.Errorf("unsupported URL scheme %q", u.Scheme)
		}

		if u.Scheme == "" && tlsInfo != nil {
			u.Scheme = "https"
		}
		if (u.Scheme == "https" || u.Scheme == "unixs") && tlsInfo == nil {
			return nil, nil, errors.Errorf("TLS key/cert must be provided for the url %s with HTTPS scheme", u.String())
		}
		if (u.Scheme == "http" || u.Scheme == "unix") && tlsInfo != nil {
			logger.KV(xlog.WARNING, "reason", "tls_without_https_scheme", "url", u.String())
		}

		ctx, cancel := context.WithCancel(context.Background())
		sctx := &serveCtx{
			network:  "tcp",
			secure:   u.Scheme == "https" || u.Scheme == "unixs",
			addr:     u.Host,
			ctx:      ctx,
			cancel:   cancel,
			cfg:      cfg,
			tlsInfo:  tlsInfo,
			gopts:    gopts,
			serversC: make(chan *servers, 2), // in case sctx.insecure,sctx.secure true
		}
		sctx.insecure = !sctx.secure

		// net.Listener will rewrite ipv4 0.0.0.0 to ipv6 [::], breaking
		// hosts that disable ipv6. So, use the address given by the user.

		if u.Scheme == "unix" || u.Scheme == "unixs" {
			sctx.network = "unix"
			sctx.addr = u.Host + u.Path
		}

		if oldctx := sctxs[sctx.addr]; oldctx != nil {
			// use existing listener
			oldctx.secure = oldctx.secure || sctx.secure
			oldctx.insecure = oldctx.insecure || sctx.insecure
			continue
		}

		logger.KV(xlog.INFO,
			"status", "listen",
			"network", sctx.network,
			"address", sctx.addr)

		if sctx.listener, err = net.Listen(sctx.network, sctx.addr); err != nil {
			return nil, nil, errors.WithStack(err)
		}
		// Registered before wrapping so the cleanup closes the raw listener
		// if the wrapper fails.
		sctxs[sctx.addr] = sctx

		if sctx.network == "tcp" {
			var kal net.Listener
			if kal, err = transport.NewKeepAliveListener(sctx.listener, sctx.network, nil); err != nil {
				return nil, nil, err
			}
			sctx.listener = kal
		}
		// TODO: register profiler, tracer, etc
	}

	return sctxs, tlsInfo, nil
}

// serve accepts incoming connections on the listener l,
// creating a new service goroutine for each. The service goroutines
// read requests and then call handler to reply to them.
func (sctx *serveCtx) serve(s *Server, errHandler func(error)) (err error) {
	// Close ranges over serversC; when serve fails before publishing its
	// servers, the channel must still be closed or Close blocks forever.
	defer sctx.closeServers()

	logger.KV(xlog.INFO, "status", "ready_to_serve", "service", s.Name(), "network", sctx.network, "address", sctx.addr)

	router := restRouter(s)

	m := cmux.New(sctx.listener)
	m.SetReadTimeout(s.cfg.Timeouts.WithDefaults().Handshake)

	// Every step that can fail runs before any server starts serving: a
	// gRPC server blocked in Accept on a cmux listener cannot be stopped
	// until m.Serve runs, so a failure must leave nothing to stop.
	var insecure, secure *servers
	var grpcL, httpL, tlsL net.Listener
	defer func() {
		if err == nil {
			return
		}
		if secure != nil {
			secure.grpc.Stop()
		}
		if insecure != nil {
			insecure.grpc.Stop()
		}
	}()

	if sctx.insecure {
		grpcL = m.Match(cmux.HTTP2())

		handler := router.Handler()
		handler = configureHandlers(s, handler)
		// rate limit will be first
		handler = configureRateLimiter(s.cfg.RateLimit, handler)
		handler = marshal.LimitRequestBody(handler, s.cfg.MaxRequestBody)
		handler = identity.NewTrustedProxyHandler(handler, s.trustedProxies)

		srv := &http.Server{
			Handler: handler,
			//ErrorLog: logger, // do not log user error
		}
		s.cfg.Timeouts.ApplyHTTP(srv)
		httpL = m.Match(cmux.HTTP1())

		insecure = &servers{grpc: grpcServer(s, nil, sctx.gopts...), http: srv}
	}

	if sctx.secure {
		tlsCfg := sctx.tlsInfo.Config()
		gs := grpcServer(s, tlsCfg, sctx.gopts...)
		handler := router.Handler()
		handler = configureHandlers(s, handler)

		// mux between http and grpc
		handler = sctx.grpcHandlerFunc(gs, handler)
		// rate limit will be first
		handler = configureRateLimiter(s.cfg.RateLimit, handler)
		// The body limit also bounds native gRPC streams here: grpc-go's
		// ServeHTTP transport buffers request data without flow control
		// (ROADMAP 12).
		handler = marshal.LimitRequestBody(handler, s.cfg.MaxRequestBody)
		handler = identity.NewTrustedProxyHandler(handler, s.trustedProxies)

		srv := &http.Server{
			Handler:   handler,
			TLSConfig: tlsCfg,
			//ErrorLog:  logger, // do not log user error
		}
		s.cfg.Timeouts.ApplyHTTP(srv)
		secure = &servers{secure: true, grpc: gs, http: srv}
		if tlsL, err = transport.NewTLSListener(m.Match(cmux.Any()), sctx.tlsInfo); err != nil {
			return err
		}
	}

	if insecure != nil {
		go func() { errHandler(insecure.grpc.Serve(grpcL)) }()
		go func() { errHandler(insecure.http.Serve(httpL)) }()
		sctx.serversC <- insecure

		logger.KV(xlog.WARNING, "reason", "insecure", "service", s.Name(), "address", sctx.addr)
	}

	if secure != nil {
		go func() { errHandler(secure.http.Serve(tlsL)) }()
		sctx.serversC <- secure
	}

	logger.KV(xlog.INFO, "status", "serving", "service", s.Name(), "address", sctx.listener.Addr().String(), "secure", sctx.secure, "insecure", sctx.insecure)

	sctx.closeServers()

	// Serve starts multiplexing the listener.
	// Serve blocks and perhaps should be invoked concurrently within a go routine.
	return m.Serve()
}

// configureRateLimiter wraps handler with the tollbooth limiter described by
// cfg, which Start has already checked with RateLimit.Validate.
func configureRateLimiter(cfg *RateLimit, handler http.Handler) http.Handler {
	if !cfg.GetEnabled() {
		return handler
	}
	logger.KV(xlog.NOTICE, "RateLimit", "enabled")

	ttl := cfg.ExpirationTTL
	if ttl == 0 {
		ttl = defaultRateLimitTTL
	}
	ops := limiter.ExpirableOptions{
		DefaultExpirationTTL: ttl,
	}

	lmt := tollbooth.NewLimiter(float64(cfg.RequestsPerSecond), &ops)
	if len(cfg.Metods) > 0 {
		lmt.SetMethods(cfg.Metods)
	}
	if len(cfg.HeadersIPLookups) > 0 {
		// Administrator override: tollbooth reads the named headers as sent.
		lmt.SetIPLookups(cfg.HeadersIPLookups)
		return tollbooth.LimitHandler(lmt, handler)
	}

	// Default: key on the client IP resolved by the trusted proxy policy.
	// tollbooth reads only RemoteAddr, so it checks a shallow copy whose
	// RemoteAddr is the bare client IP; tollbooth also echoes that IP in
	// X-Rate-Limit-Request-Remote-Addr. The handler and the OnLimitReached
	// callback receive the original request. An empty IP is not limited.
	lmt.SetIPLookups([]string{rateLookupRemoteAddr})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limitReq := *r
		limitReq.RemoteAddr = identity.ClientIPFromRequest(r)
		if httpErr := tollbooth.LimitByRequest(lmt, w, &limitReq); httpErr != nil {
			// Same response as tollbooth.LimitHandler.
			lmt.ExecOnLimitReached(w, r)
			if lmt.GetOverrideDefaultResponseWriter() {
				return
			}
			w.Header().Add(header.ContentType, lmt.GetMessageContentType())
			w.WriteHeader(httpErr.StatusCode)
			_, _ = w.Write([]byte(httpErr.Message))
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func configureHandlers(s *Server, handler http.Handler) http.Handler {
	// NOTE: the handlers are executed in the reverse order
	// therefore configure additional first
	for _, other := range s.opts.handlers {
		handler = other(handler)
	}

	// service ready
	handler = ready.NewServiceStatusVerifier(s, handler)

	var err error
	// authz
	if s.authz != nil {
		handler, err = s.authz.NewHandler(handler)
		if err != nil {
			logger.Panicf("failed to create authz handler: %+v", err)
		}
	}

	// logging wrapper
	var opts []telemetry.Option
	if len(s.cfg.SkipLogPaths) > 0 {
		opts = append(opts, telemetry.WithLoggerSkipPaths(s.cfg.SkipLogPaths))
	}
	handler = telemetry.NewRequestLogger(handler, time.Millisecond, logger, opts...)

	// metrics wrapper
	handler = telemetry.NewRequestMetrics(handler)

	// role/contextID wrapper
	handler = identity.NewContextHandler(handler, s.identity.IdentityFromRequest)

	if s.cfg.CORS.GetEnabled() {
		logger.KV(xlog.NOTICE, "server", s.name, "CORS", "enabled")
		handler = corsHandler(s.cfg.CORS, handler)
	}

	// Add correlationID
	handler = correlation.NewHandler(handler)

	return handler
}

func corsHandler(cfg *CORS, handler http.Handler) http.Handler {
	allowedOrigins := cfg.AllowedOrigins
	options := cors.Options{
		AllowedOrigins:     allowedOrigins,
		AllowedMethods:     cfg.AllowedMethods,
		AllowedHeaders:     cfg.AllowedHeaders,
		ExposedHeaders:     cfg.ExposedHeaders,
		MaxAge:             cfg.MaxAge,
		AllowCredentials:   cfg.GetAllowCredentials(),
		OptionsPassthrough: cfg.GetOptionsPassthrough(),
		Debug:              cfg.GetDebug(),
	}
	if len(allowedOrigins) == 0 {
		// rs/cors treats an empty list as allow-all; an enabled CORS block
		// with no origins allows none, matching gRPC-Web. "*" with
		// credentials never reaches here: CORS.Validate rejects it.
		options.AllowOriginVaryRequestFunc = func(_ *http.Request, _ string) (bool, []string) {
			return false, nil
		}
	}
	co := cors.New(options)
	return co.Handler(handler)
}

func restRouter(e *Server) restserver.Router {
	router := restserver.NewRouter(notFoundHandler)

	for name, svc := range e.services {
		if registrator, ok := svc.(RouteRegistrator); ok {
			logger.KV(xlog.INFO, "status", "RouteRegistrator", "server", e.Name(), "service", name)

			registrator.RegisterRoute(router)
		} else {
			logger.KV(xlog.INFO, "status", "not_supported_RouteRegistrator", "server", e.Name(), "service", name)
		}
	}

	return router
}

func grpcServer(s *Server, tls *tls.Config, gopts ...grpc.ServerOption) *grpc.Server {
	var opts []grpc.ServerOption
	//opts = append(opts, grpc.CustomCodec(&codec{}))

	if tls != nil {
		bundle := credentials.NewBundle(credentials.Config{TLSConfig: tls})
		opts = append(opts, grpc.Creds(bundle.TransportCredentials()))
	}

	chainUnaryInterceptors := []grpc.UnaryServerInterceptor{
		panicInterceptor(),
		NewRequestValidationUnaryInterceptor(),
		correlation.NewAuthUnaryInterceptor(),
		s.newLogUnaryInterceptor(),
		identity.NewAuthUnaryInterceptor(s.identity.IdentityFromContext, s.trustedProxies),
	}
	// authz is nil when the config has no allow rules; the interceptors
	// would dereference it on every call.
	if s.authz != nil {
		chainUnaryInterceptors = append(chainUnaryInterceptors, s.authz.NewUnaryInterceptor())
	}
	if s.cfg.PromGrpc {
		chainUnaryInterceptors = append(chainUnaryInterceptors, grpc_prometheus.UnaryServerInterceptor)
	}
	if len(s.opts.unary) > 0 {
		chainUnaryInterceptors = append(chainUnaryInterceptors, s.opts.unary...)
	}

	chainStreamInterceptors := []grpc.StreamServerInterceptor{
		s.newLogStreamServerInterceptor(),
		correlation.NewStreamServerInterceptor(),
		identity.NewStreamServerInterceptor(s.identity.IdentityFromContext, s.trustedProxies),
	}
	if s.authz != nil {
		chainStreamInterceptors = append(chainStreamInterceptors, s.authz.NewStreamServerInterceptor())
	}
	if s.cfg.PromGrpc {
		chainStreamInterceptors = append(chainStreamInterceptors, grpc_prometheus.StreamServerInterceptor)
	}
	if len(s.opts.stream) > 0 {
		chainStreamInterceptors = append(chainStreamInterceptors, s.opts.stream...)
	}

	opts = append(opts, grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(chainUnaryInterceptors...)))
	opts = append(opts, grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(chainStreamInterceptors...)))

	if s.opts.maxRecvMsgSize > 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(s.opts.maxRecvMsgSize))
	} else if s.cfg.MaxRecvMsgSize > 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(s.cfg.MaxRecvMsgSize))
	}
	if s.opts.maxSendMsgSize > 0 {
		opts = append(opts, grpc.MaxSendMsgSize(s.opts.maxSendMsgSize))
	} else if s.cfg.MaxSendMsgSize > 0 {
		opts = append(opts, grpc.MaxSendMsgSize(s.cfg.MaxSendMsgSize))
	}

	grpcServer := grpc.NewServer(append(opts, gopts...)...)

	for name, svc := range s.services {
		if registrator, ok := svc.(GRPCRegistrator); ok {
			logger.KV(xlog.INFO, "status", "RegisterGRPC", "server", s.Name(), "service", name)

			registrator.RegisterGRPC(grpcServer)
		} else {
			logger.KV(xlog.INFO, "status", "not_supported_RegisterGRPC", "server", s.Name(), "service", name)
		}
	}

	return grpcServer
}

func panicInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, si *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (res any, err error) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.ContextKV(ctx, xlog.ERROR,
					"reason", "panic",
					"action", si.FullMethod,
					"err", rec,
					"stack", string(debug.Stack()))
				err = httperror.NewGrpcFromCtx(ctx, codes.Internal, "unhandled exception")
			}
		}()
		return handler(ctx, req)
	}
}

// grpcHandlerFunc returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise. Given in gRPC docs.
func (sctx *serveCtx) grpcHandlerFunc(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	if otherHandler == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.ContextKV(r.Context(), xlog.ERROR,
						"reason", "panic",
						"err", rec,
						"stack", string(debug.Stack()))
					http.Error(w, "unhandled exception", http.StatusInternalServerError)
				}
			}()
			grpcServer.ServeHTTP(w, r)
		})
	}

	corsEnabled := sctx.cfg.CORS.GetEnabled()
	var allowedOrigins []string
	exposedHeaders := ""
	allowCredentials := false
	var originMatcher *cors.Cors
	wildcard := false
	if corsEnabled {
		allowedOrigins = sctx.cfg.CORS.AllowedOrigins
		wildcard = slices.Contains(allowedOrigins, corsWildcardOrigin)
		originMatcher = cors.New(cors.Options{AllowedOrigins: allowedOrigins})
		if len(sctx.cfg.CORS.ExposedHeaders) > 0 {
			exposedHeaders = strings.Join(sctx.cfg.CORS.ExposedHeaders, ", ")
		}
		allowCredentials = sctx.cfg.CORS.GetAllowCredentials()
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.ContextKV(r.Context(), xlog.ERROR,
					"reason", "panic",
					"err", rec,
					"stack", string(debug.Stack()))
				http.Error(w, "unhandled exception", http.StatusInternalServerError)
			}
		}()

		if len(sctx.cfg.HTTPHeaders) > 0 {
			wh := w.Header()
			for k, v := range sctx.cfg.HTTPHeaders {
				wh.Set(k, v)
			}
		}

		ct := r.Header.Get(header.ContentType)
		if strings.HasPrefix(ct, header.ApplicationGRPC) {
			origin := r.Header.Get("Origin")
			grpcWeb := (ct == header.ApplicationGRPCWebProto || ct == header.ApplicationGRPCWebText)
			wh := w.Header()
			if grpcWeb {
				if r.ProtoMajor != 2 {
					// logger.ContextKV(r.Context(), xlog.INFO,
					// 	"reason", "http2_required",
					// 	"method", r.Method,
					// 	"major", r.ProtoMajor,
					// 	"proto", r.Proto,
					// )
					r.ProtoMajor, r.ProtoMinor, r.Proto = 2, 0, "HTTP/2.0"
				}
				if ct == header.ApplicationGRPCWebText {
					// For grpc-web-text, the body is base64 encoded.
					// So we need to decode it before passing it to the gRPC server.
					decodedReader := base64.NewDecoder(base64.StdEncoding, r.Body)
					r.Body = io.NopCloser(decodedReader)
				}

				// Remove content-length header since it represents http1.1 payload size, not the sum of the h2
				// DATA frame payload lengths. https://http2.github.io/http2-spec/#malformed This effectively
				// switches to chunked encoding which is the default for h2
				r.Header.Del(header.ContentLength)

				r.Header.Set(header.ContentType, header.ApplicationGRPC)
				if origin != "" && corsEnabled {
					if len(allowedOrigins) == 0 || !originMatcher.OriginAllowed(r) {
						logger.ContextKV(r.Context(), xlog.INFO,
							"reason", "cors_not_allowed",
							"method", r.Method,
							"ct", ct,
							"remote", r.RemoteAddr,
							"agent", r.UserAgent(),
							"content-type", r.Header.Get(header.ContentType),
							"accept", r.Header.Get(header.Accept),
							"url", r.URL.String())
						wh.Add(header.Vary, "Origin")
						http.Error(w, "origin not allowed", http.StatusForbidden)
						return
					}
					if wildcard {
						// Never credentialed: CORS.Validate rejects "*" with
						// credentials, and the header is not sent here either.
						wh.Set("Access-Control-Allow-Origin", corsWildcardOrigin)
					} else {
						wh.Set("Access-Control-Allow-Origin", origin)
						wh.Add(header.Vary, "Origin")
						if allowCredentials {
							wh.Set("Access-Control-Allow-Credentials", "true")
						}
					}
					if exposedHeaders != "" {
						wh.Set("Access-Control-Expose-Headers", exposedHeaders)
					}
				}

				// Only apply HTTP-level gzip for unary (non-streaming) calls.
				// Streaming calls are flagged by the client via the
				// header.XGRPCStream header; gzip-ing a stream forces the body
				// to be buffered (fixed Content-Length) and swallows per-message
				// flushes, which breaks streaming.
				// Accept-Encoding is matched by substring, so q-values are
				// ignored (FINDINGS P-076).
				isStream := r.Header.Get(header.XGRPCStream) != ""
				compress := !isStream && strings.Contains(r.Header.Get(header.AcceptEncoding), header.Gzip)
				grw := newGrpcWebResponse(w, ct, compress)
				grw.exposeHeaders = corsEnabled && origin != ""
				w = grw
				defer func() {
					grw := w.(*grpcWebResponse)
					grw.Close()
				}()
			}
			if !grpcWeb && r.ProtoMajor == 2 {
				clearStreamReadDeadline(w, r)
			}
			if sctx.cfg.DebugLogs {
				logger.ContextKV(r.Context(), xlog.DEBUG,
					"method", r.Method,
					"ct", ct,
					"remote", r.RemoteAddr,
					"agent", r.UserAgent(),
					"content-type", r.Header.Get(header.ContentType),
					"accept", r.Header.Get(header.Accept),
					"content-length", r.ContentLength,
					"proto_ver_minor", r.ProtoMinor,
					"proto_ver_major", r.ProtoMajor,
					"url", r.URL.String())
			}
			grpcServer.ServeHTTP(w, r)
			if grpcWeb {
				grw := w.(*grpcWebResponse)
				grw.finishRequest()
				if sctx.cfg.DebugLogs {
					logger.ContextKV(r.Context(), xlog.DEBUG,
						"method", r.Method,
						"headers", grw.headers,
					)
				}
			}
		} else {
			if sctx.cfg.DebugLogs && r.URL.Path != "/healthz" {
				logger.ContextKV(r.Context(), xlog.DEBUG,
					"handle", "otherHandler",
					"ct", ct,
					"remote", r.RemoteAddr,
					"agent", r.UserAgent(),
					"content-type", r.Header.Get(header.ContentType),
					"accept", r.Header.Get(header.Accept),
					"content-length", r.ContentLength,
					"method", r.Method,
					"url", r.URL.String(),
					"proto_ver_minor", r.ProtoMinor,
					"proto_ver_major", r.ProtoMajor)
			}
			otherHandler.ServeHTTP(w, r)
		}
	})

	return handler
}

// clearStreamReadDeadline removes the HTTP/2 per-stream ReadTimeout from a
// native gRPC request, so client-streaming and bidi RPCs on TLS listeners
// are not cut after Timeouts.Read, as on plaintext listeners. The stream
// stays bounded by MaxRequestBody.
func clearStreamReadDeadline(w http.ResponseWriter, r *http.Request) {
	if err := http.NewResponseController(w).SetReadDeadline(time.Time{}); err != nil {
		logger.ContextKV(r.Context(), xlog.WARNING,
			"reason", "clear_read_deadline",
			"path", r.URL.Path,
			"err", err.Error())
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	marshal.WriteJSON(w, r, httperror.NotFound("%s", r.URL.Path))
}

// Validator is implemented by request messages that can validate themselves;
// NewRequestValidationUnaryInterceptor calls it before the handler.
type Validator interface {
	// Validate returns an error (typically a gRPC status) when the request is invalid.
	Validate(ctx context.Context) error
}

// NewRequestValidationUnaryInterceptor returns a unary interceptor that calls
// Validate on requests implementing Validator and rejects the call with the
// returned error. It is always installed by Start.
func NewRequestValidationUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, si *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (res any, err error) {
		if validator, ok := req.(Validator); ok {
			if err := validator.Validate(ctx); err != nil {
				return nil, err
			}
		}
		return handler(ctx, req)
	}
}
