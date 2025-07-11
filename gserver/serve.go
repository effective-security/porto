package gserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

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
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xlog"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/pkg/errors"
	"github.com/rs/cors"
	"github.com/soheilhy/cmux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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

	gopts    []grpc.ServerOption
	serversC chan *servers
}

type servers struct {
	secure bool
	grpc   *grpc.Server
	http   *http.Server
}

func configureListeners(cfg *Config) (sctxs map[string]*serveCtx, err error) {
	urls, err := cfg.ParseListenURLs()
	if err != nil {
		return nil, err
	}

	var tlsInfo *transport.TLSInfo
	if !cfg.ServerTLS.Empty() {
		from := cfg.ServerTLS
		clientauthType := tls.VerifyClientCertIfGiven
		if from.GetClientCertAuth() {
			clientauthType = tls.RequireAndVerifyClientCert
		}
		tlsInfo = &transport.TLSInfo{
			CertFile:       from.CertFile,
			KeyFile:        from.KeyFile,
			TrustedCAFile:  from.TrustedCAFile,
			ClientCAFile:   from.ClientCAFile,
			ClientAuthType: clientauthType,
			CipherSuites:   from.CipherSuites,
			// CRLVerifier : TODO
		}

		_, err = tlsInfo.ServerTLSWithReloader()
		if err != nil {
			return nil, err
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

	sctxs = make(map[string]*serveCtx)
	defer func() {
		if err == nil {
			return
		}
		// clean up on error
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
	}()

	for _, u := range urls {
		if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "unix" && u.Scheme != "unixs" {
			return nil, errors.Errorf("unsupported URL scheme %q", u.Scheme)
		}

		if u.Scheme == "" && tlsInfo != nil {
			u.Scheme = "https"
		}
		if (u.Scheme == "https" || u.Scheme == "unixs") && tlsInfo == nil {
			return nil, errors.Errorf("TLS key/cert must be provided for the url %s with HTTPS scheme", u.String())
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
			return nil, errors.WithStack(err)
		}

		if sctx.network == "tcp" {
			if sctx.listener, err = transport.NewKeepAliveListener(sctx.listener, sctx.network, nil); err != nil {
				return nil, err
			}
		}
		// TODO: register profiler, tracer, etc

		sctxs[sctx.addr] = sctx
	}

	return sctxs, nil
}

// serve accepts incoming connections on the listener l,
// creating a new service goroutine for each. The service goroutines
// read requests and then call handler to reply to them.
func (sctx *serveCtx) serve(s *Server, errHandler func(error)) (err error) {
	//<-s.ReadyNotify()

	logger.KV(xlog.INFO, "status", "ready_to_serve", "service", s.Name(), "network", sctx.network, "address", sctx.addr)

	var gsSecure *grpc.Server
	var gsInsecure *grpc.Server

	defer func() {
		if err == nil {
			return
		}
		if gsSecure != nil {
			gsSecure.Stop()
		}
		if gsInsecure != nil {
			gsInsecure.Stop()
		}
	}()

	router := restRouter(s)

	m := cmux.New(sctx.listener)

	if sctx.insecure {
		gsInsecure = grpcServer(s, nil, sctx.gopts...)
		grpcL := m.Match(cmux.HTTP2())
		go func() { errHandler(gsInsecure.Serve(grpcL)) }()

		handler := router.Handler()
		handler = configureHandlers(s, handler)
		// rate limit will be first
		handler = configureRateLimiter(s.cfg.RateLimit, handler)

		srv := &http.Server{
			Handler: handler,
			//ErrorLog: logger, // do not log user error
		}

		httpL := m.Match(cmux.HTTP1())
		go func() { errHandler(srv.Serve(httpL)) }()

		sctx.serversC <- &servers{grpc: gsInsecure, http: srv}

		logger.KV(xlog.WARNING, "reason", "insecure", "service", s.Name(), "address", sctx.addr)
	}

	if sctx.secure {
		gsSecure = grpcServer(s, sctx.tlsInfo.Config(), sctx.gopts...)
		handler := router.Handler()
		handler = configureHandlers(s, handler)

		// mux between http and grpc
		handler = sctx.grpcHandlerFunc(gsSecure, handler)
		// rate limit will be first
		handler = configureRateLimiter(s.cfg.RateLimit, handler)

		srv := &http.Server{
			Handler:   handler,
			TLSConfig: sctx.tlsInfo.Config(),
			//ErrorLog:  logger, // do not log user error
		}
		grpcL, err := transport.NewTLSListener(m.Match(cmux.Any()), sctx.tlsInfo)
		if err != nil {
			return err
		}
		go func() { errHandler(srv.Serve(grpcL)) }()

		sctx.serversC <- &servers{secure: true, grpc: gsSecure, http: srv}
	}

	logger.KV(xlog.INFO, "status", "serving", "service", s.Name(), "address", sctx.listener.Addr().String(), "secure", sctx.secure, "insecure", sctx.insecure)

	close(sctx.serversC)

	// Serve starts multiplexing the listener.
	// Serve blocks and perhaps should be invoked concurrently within a go routine.
	return m.Serve()
}

func configureRateLimiter(cfg *RateLimit, handler http.Handler) http.Handler {
	if !cfg.GetEnabled() {
		return handler
	}
	logger.KV(xlog.NOTICE, "RateLimit", "enabled")

	ttl := cfg.ExpirationTTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	ops := limiter.ExpirableOptions{
		DefaultExpirationTTL: ttl,
	}

	lmt := tollbooth.NewLimiter(float64(cfg.RequestsPerSecond), &ops)
	if len(cfg.HeadersIPLookups) > 0 {
		lmt.SetIPLookups(cfg.HeadersIPLookups)
	}
	if len(cfg.Metods) > 0 {
		lmt.SetMethods(cfg.Metods)
	}

	return tollbooth.LimitHandler(lmt, handler)
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
		co := cors.New(cors.Options{
			AllowedOrigins: s.cfg.CORS.AllowedOrigins,
			//AllowOriginFunc:        s.cfg.CORS.AllowOriginFunc,
			//AllowOriginRequestFunc: s.cfg.CORS.AllowOriginRequestFunc,
			AllowedMethods:     s.cfg.CORS.AllowedMethods,
			AllowedHeaders:     s.cfg.CORS.AllowedHeaders,
			ExposedHeaders:     s.cfg.CORS.ExposedHeaders,
			MaxAge:             s.cfg.CORS.MaxAge,
			AllowCredentials:   s.cfg.CORS.GetAllowCredentials(),
			OptionsPassthrough: s.cfg.CORS.GetOptionsPassthrough(),
			Debug:              s.cfg.CORS.GetDebug(),
		})
		handler = co.Handler(handler)
	}

	// Add correlationID
	handler = correlation.NewHandler(handler)

	return handler
}

func restRouter(s *Server) restserver.Router {
	router := restserver.NewRouter(notFoundHandler)

	for name, svc := range s.services {
		if registrator, ok := svc.(RouteRegistrator); ok {
			logger.KV(xlog.INFO, "status", "RouteRegistrator", "server", s.Name(), "service", name)

			registrator.RegisterRoute(router)
		} else {
			logger.KV(xlog.INFO, "status", "not_supported_RouteRegistrator", "server", s.Name(), "service", name)
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
		correlation.NewAuthUnaryInterceptor(),
		s.newLogUnaryInterceptor(),
		identity.NewAuthUnaryInterceptor(s.identity.IdentityFromContext),
		s.authz.NewUnaryInterceptor(),
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
		identity.NewStreamServerInterceptor(s.identity.IdentityFromContext),
		s.authz.NewStreamServerInterceptor(),
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
	return func(ctx context.Context, req interface{}, si *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (res any, err error) {
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

	var allowedOrigins []string
	exposedHeaders := ""
	if sctx.cfg.CORS != nil {
		if len(sctx.cfg.CORS.AllowedOrigins) > 0 && sctx.cfg.CORS.AllowedOrigins[0] != "*" {
			allowedOrigins = sctx.cfg.CORS.AllowedOrigins
		}
		if len(sctx.cfg.CORS.ExposedHeaders) > 0 {
			exposedHeaders = strings.Join(sctx.cfg.CORS.ExposedHeaders, ",")
		}
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
				if origin != "" {
					if len(allowedOrigins) > 0 && !slices.ContainsString(allowedOrigins, origin) {
						logger.ContextKV(r.Context(), xlog.INFO,
							"reason", "cors_not_allowed",
							"method", r.Method,
							"ct", ct,
							"remote", r.RemoteAddr,
							"agent", r.UserAgent(),
							"content-type", r.Header.Get(header.ContentType),
							"accept", r.Header.Get(header.Accept),
							"url", r.URL.String())
						return
					}
					if len(allowedOrigins) > 0 {
						wh.Set("Access-Control-Allow-Origin", origin)
					} else {
						wh.Set("Access-Control-Allow-Origin", "*")
					}
				}
				if exposedHeaders != "" {
					wh.Set("Access-Control-Expose-Headers", exposedHeaders)
				}

				w = newGrpcWebResponse(w, ct)
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

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	marshal.WriteJSON(w, r, httperror.NotFound("%s", r.URL.Path))
}
