package restserver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/porto/restserver/ready"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/x/netutil"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto", "rest")

// MaxRequestSize is the recommended maximum size in bytes (64 MiB) of a regular
// HTTP POST body. The server does not enforce it; handlers that read bodies
// should wrap r.Body with http.MaxBytesReader(w, r.Body, MaxRequestSize).
const MaxRequestSize = 64 * 1024 * 1024

// Event source and message names that services may use when reporting
// lifecycle status (for example to an audit log).
const (
	// EvtSourceStatus is the event source name for service status events.
	EvtSourceStatus = "status"
	// EvtServiceStarted is the event message for a started service.
	EvtServiceStarted = "service started"
	// EvtServiceStopped is the event message for a stopped service.
	EvtServiceStopped = "service stopped"
)

// ServerEvent identifies a server lifecycle event delivered to OnEvent handlers.
type ServerEvent int

const (
	// ServerStartedEvent is fired on server start
	ServerStartedEvent ServerEvent = iota
	// ServerStoppedEvent is fired after server stopped
	ServerStoppedEvent
	// ServerStoppingEvent is fired before server stopped
	ServerStoppingEvent
)

// ServerEventFunc is a callback invoked synchronously when a ServerEvent is
// broadcast. ServerStartedEvent is delivered on the serving goroutine;
// ServerStoppingEvent and ServerStoppedEvent on the StopHTTP caller.
type ServerEventFunc func(evt ServerEvent)

// Server is the interface exposed to services and middleware for querying
// server identity, configuration and lifecycle. *HTTPServer is the
// implementation; services receive it via their constructors.
type Server interface {
	http.Handler
	// Name returns the configured server name (Config.GetServerName).
	Name() string
	// Version returns the version string passed to New.
	Version() string
	// HostName returns the host part of the bind address, or the OS hostname.
	HostName() string
	// LocalIP returns the IP address passed to New, or the auto-detected local IP.
	LocalIP() string
	// Port returns the port part of the bind address.
	Port() string
	// Protocol returns "https" when a TLS config is set, "http" otherwise.
	Protocol() string
	// PublicURL returns Config.GetPublicURL.
	PublicURL() string
	// StartedAt returns the UTC time the server instance was created.
	StartedAt() time.Time
	// Service returns a registered service by name, or nil.
	Service(name string) Service
	// Config returns the server configuration.
	Config() Config
	// TLSConfig returns the TLS configuration, or nil for plain HTTP.
	TLSConfig() *tls.Config

	// IsReady indicates that the server is serving and all services are ready to serve
	IsReady() bool

	// AddService registers a service; it must be called before StartHTTP.
	AddService(s Service)
	// StartHTTP starts serving in a background goroutine.
	StartHTTP() error
	// StopHTTP closes services and gracefully shuts down the listener.
	StopHTTP()

	// OnEvent registers a handler for a lifecycle event.
	OnEvent(evt ServerEvent, handler ServerEventFunc)
}

// MuxFactory creates the root http.Handler used by StartHTTP. HTTPServer is
// its own default MuxFactory (see HTTPServer.NewMux); use WithMuxFactory to
// substitute a custom middleware chain.
type MuxFactory interface {
	// NewMux builds and returns the root handler.
	NewMux() http.Handler
}

// HTTPServer exposes a collection of Service implementations as a single
// HTTP or HTTPS server. Configure it with the With* methods and AddService
// before calling StartHTTP; those setters are not synchronised against a
// running server.
//
// The embedded Server interface is left nil: only the methods implemented
// directly on *HTTPServer are usable (note that Config() is not, use
// HTTPConfig()).
type HTTPServer struct {
	Server
	authz           authz.HTTPAuthz
	identityMapper  identity.ProviderFromRequest
	httpConfig      Config
	tlsConfig       *tls.Config
	httpServer      *http.Server
	cors            *CORSOptions
	muxFactory      MuxFactory
	hostname        string
	port            string
	ipaddr          string
	version         string
	serving         atomic.Bool
	startedAt       time.Time
	clientAuth      string
	services        map[string]Service
	evtHandlers     map[ServerEvent][]ServerEventFunc
	lock            sync.RWMutex
	shutdownTimeout time.Duration
}

// New creates a server for the given configuration. version is reported by
// Version(); ipaddr is the address reported by LocalIP() and is auto-detected
// (falling back to 127.0.0.1) when empty; a nil tlsConfig serves plain HTTP.
// The default shutdown timeout is 5 seconds. New never returns an error today.
func New(
	version string,
	ipaddr string,
	httpConfig Config,
	tlsConfig *tls.Config,
) (*HTTPServer, error) {
	var err error

	// TODO: shall extract from bindAddr?
	if ipaddr == "" {
		ipaddr, err = netutil.GetLocalIP()
		if err != nil {
			ipaddr = "127.0.0.1"
			logger.KV(xlog.ERROR, "reason", "unable_determine_ipaddr", "use", ipaddr, "err", err)
		}
	}

	s := &HTTPServer{
		services:    map[string]Service{},
		startedAt:   time.Now().UTC(),
		version:     version,
		ipaddr:      ipaddr,
		evtHandlers: make(map[ServerEvent][]ServerEventFunc),
		clientAuth:  tlsClientAuthToStrMap[tls.NoClientCert],
		httpConfig:  httpConfig,
		// TODO: hostname shall be from os.Host
		hostname:        GetHostName(httpConfig.GetBindAddr()),
		port:            GetPort(httpConfig.GetBindAddr()),
		tlsConfig:       tlsConfig,
		shutdownTimeout: time.Duration(5) * time.Second,
	}
	s.muxFactory = s
	if tlsConfig != nil {
		s.clientAuth = tlsClientAuthToStrMap[tlsConfig.ClientAuth]
	}

	return s, nil
}

// WithAuthz enables path/role authorization; the handler is created from
// authz by NewMux, so it must be set before StartHTTP.
func (server *HTTPServer) WithAuthz(authz authz.HTTPAuthz) *HTTPServer {
	server.authz = authz
	return server
}

// WithIdentityProvider sets the mapper that derives the caller identity for
// each request. When unset identity.GuestIdentityMapper is used.
func (server *HTTPServer) WithIdentityProvider(provider identity.ProviderFromRequest) *HTTPServer {
	server.identityMapper = provider
	return server
}

// WithCORS enables the CORS middleware around the router with the given
// options; nil options disable CORS.
func (server *HTTPServer) WithCORS(cors *CORSOptions) *HTTPServer {
	server.cors = cors
	return server
}

// WithShutdownTimeout sets how long StopHTTP waits for in-flight requests to
// drain before giving up (default 5s).
func (server *HTTPServer) WithShutdownTimeout(timeout time.Duration) *HTTPServer {
	server.shutdownTimeout = timeout
	return server
}

var tlsClientAuthToStrMap = map[tls.ClientAuthType]string{
	tls.NoClientCert:               "NoClientCert",
	tls.RequestClientCert:          "RequestClientCert",
	tls.RequireAnyClientCert:       "RequireAnyClientCert",
	tls.VerifyClientCertIfGiven:    "VerifyClientCertIfGiven",
	tls.RequireAndVerifyClientCert: "RequireAndVerifyClientCert",
}

// AddService registers a service by its Name. It panics (via the logger) if a
// service with the same name is already registered. Call it before StartHTTP.
func (server *HTTPServer) AddService(s Service) {
	server.lock.Lock()
	defer server.lock.Unlock()
	if server.services[s.Name()] != nil {
		logger.Panicf("service already registered: %s", s.Name())
	}
	server.services[s.Name()] = s
}

// OnEvent registers a callback for the given lifecycle event. Handlers are
// invoked synchronously in registration order.
func (server *HTTPServer) OnEvent(evt ServerEvent, handler ServerEventFunc) {
	server.lock.Lock()
	defer server.lock.Unlock()

	server.evtHandlers[evt] = append(server.evtHandlers[evt], handler)
}

// Service returns the registered service with the given name, or nil.
func (server *HTTPServer) Service(name string) Service {
	server.lock.Lock()
	defer server.lock.Unlock()
	return server.services[name]
}

// HostName returns the host name of the server
func (server *HTTPServer) HostName() string {
	return server.hostname
}

// Port returns the port part of the bind address (see GetPort).
func (server *HTTPServer) Port() string {
	return server.port
}

// Protocol returns "https" when a TLS config was supplied, otherwise "http".
func (server *HTTPServer) Protocol() string {
	if server.tlsConfig != nil {
		return "https"
	}
	return "http"
}

// LocalIP returns the IP address passed to New, or the auto-detected local IP.
func (server *HTTPServer) LocalIP() string {
	return server.ipaddr
}

// PublicURL returns the configured public URL (Config.GetPublicURL).
func (server *HTTPServer) PublicURL() string {
	return server.httpConfig.GetPublicURL()
}

// StartedAt returns the UTC time at which the server instance was created.
func (server *HTTPServer) StartedAt() time.Time {
	return server.startedAt
}

// Uptime returns the time elapsed since StartedAt.
func (server *HTTPServer) Uptime() time.Duration {
	return time.Now().UTC().Sub(server.startedAt)
}

// Version returns the version string passed to New.
func (server *HTTPServer) Version() string {
	return server.version
}

// Name returns the configured server name (Config.GetServerName).
func (server *HTTPServer) Name() string {
	return server.httpConfig.GetServerName()
}

// HTTPConfig returns the Config passed to New.
func (server *HTTPServer) HTTPConfig() Config {
	return server.httpConfig
}

// TLSConfig returns the TLS configuration passed to New, or nil for plain HTTP.
func (server *HTTPServer) TLSConfig() *tls.Config {
	return server.tlsConfig
}

// IsReady reports whether the listener has been started and every registered
// service reports IsReady. It is used by the ready middleware to answer 503
// until then.
func (server *HTTPServer) IsReady() bool {
	if !server.serving.Load() {
		return false
	}
	server.lock.RLock()
	defer server.lock.RUnlock()
	for _, ss := range server.services {
		if !ss.IsReady() {
			return false
		}
	}
	return true
}

// WithMuxFactory replaces the factory used by StartHTTP to build the root
// handler, allowing a custom middleware chain instead of NewMux.
func (server *HTTPServer) WithMuxFactory(muxFactory MuxFactory) {
	server.muxFactory = muxFactory
}

func (server *HTTPServer) broadcast(evt ServerEvent) {
	for _, handler := range server.evtHandlers[evt] {
		handler(evt)
	}
}

// StartHTTP builds the handler via the MuxFactory and starts serving in a
// background goroutine, returning immediately. With TLS the listener is bound
// synchronously and bind errors are returned; for plain HTTP the listener is
// bound inside the goroutine and a failure there (for example address in
// use) panics via the logger. ServerStartedEvent is broadcast from the
// serving goroutine.
func (server *HTTPServer) StartHTTP() error {
	bindAddr := server.httpConfig.GetBindAddr()
	var err error

	// Main server
	if _, err = net.ResolveTCPAddr("tcp", bindAddr); err != nil {
		return errors.WithMessagef(err, "unable to resolve address")
	}

	server.httpServer = &http.Server{
		IdleTimeout: time.Hour, // TODO: via config
		ErrorLog:    xlog.Stderr,
	}

	var httpsListener net.Listener

	if server.tlsConfig != nil {
		// Start listening on main server over TLS
		httpsListener, err = tls.Listen("tcp", bindAddr, server.tlsConfig)
		if err != nil {
			return errors.WithMessagef(err, "%s: unable to listen: %q",
				server.Name(), bindAddr)
		}

		server.httpServer.TLSConfig = server.tlsConfig
	} else {
		server.httpServer.Addr = bindAddr
	}

	httpHandler := server.muxFactory.NewMux()

	/*
		if server.httpConfig.GetAllowProfiling() {
			httpHandler, err = telemetry.NewRequestProfiler(httpHandler, server.httpConfig.GetProfilerDir(), nil, telemetry.LogProfile())
			if  err != nil {
				return errors.WithStack(err)
			}
		}
	*/

	server.httpServer.Handler = httpHandler

	serve := func() error {
		server.serving.Store(true)
		if httpsListener != nil {
			return server.httpServer.Serve(httpsListener)
		}
		return server.httpServer.ListenAndServe()
	}

	go func() {
		server.broadcast(ServerStartedEvent)

		logger.KV(xlog.INFO, "server", server.Name(), "bind", bindAddr, "status", "starting", "protocol", server.Protocol())

		// this is a blocking call to serve
		if err := serve(); err != nil {
			server.serving.Store(false)
			// panic, only if not Serve error while stopping the server,
			// which is a valid error
			if netutil.IsAddrInUse(err) || err != http.ErrServerClosed {
				logger.Panicf("server=%s, err=[%v]", server.Name(), errors.WithStack(err))
			}
			logger.KV(xlog.WARNING, "server", server.Name(), "status", "stopped", "reason", err.Error())
		}
	}()

	return nil
}

// StopHTTP performs a graceful shutdown: it broadcasts ServerStoppingEvent,
// calls Close on every registered service, then calls http.Server.Shutdown
// bounded by the shutdown timeout (see WithShutdownTimeout) so in-flight
// requests can drain, and finally broadcasts ServerStoppedEvent. Shutdown
// errors are logged, not returned. StopHTTP must only be called after a
// successful StartHTTP, and the instance must not be reused afterwards.
func (server *HTTPServer) StopHTTP() {
	server.broadcast(ServerStoppingEvent)

	// close services
	for _, f := range server.services {
		logger.KV(xlog.TRACE, "service", f.Name(), "status", "closing")
		f.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), server.shutdownTimeout)
	defer cancel()
	err := server.httpServer.Shutdown(ctx)
	if err != nil {
		logger.KV(xlog.ERROR, "reason", "Shutdown", "err", err)
	}
	server.broadcast(ServerStoppedEvent)
}

// NewMux builds the default handler chain: a Router (with CORS when
// configured) on which every registered service has called Register, wrapped
// (innermost to outermost) by the ready verifier, the authz handler when set,
// the request logger, request metrics, the identity context handler and the
// correlation ID handler. It is called by StartHTTP through the MuxFactory;
// call it directly only in tests. It panics via the logger if the authz
// handler cannot be created.
func (server *HTTPServer) NewMux() http.Handler {
	// NOTE: the handlers are executed in the reverse order

	var router Router
	if server.cors != nil {
		router = NewRouterWithCORS(notFoundHandler, server.cors)
	} else {
		router = NewRouter(notFoundHandler)
	}

	for _, f := range server.services {
		f.Register(router)
	}
	logger.KV(xlog.DEBUG, "server", server.Name(), "service_count", len(server.services))

	var err error
	httpHandler := router.Handler()

	logger.KV(xlog.INFO, "server", server.Name(), "ClientAuth", server.clientAuth)

	// service ready
	httpHandler = ready.NewServiceStatusVerifier(server, httpHandler)

	if server.authz != nil {
		httpHandler, err = server.authz.NewHandler(httpHandler)
		if err != nil {
			logger.Panicf("failed to create authz handler: %+v", err)
		}
	}

	// logging wrapper
	httpHandler = telemetry.NewRequestLogger(
		httpHandler,
		time.Millisecond,
		logger)

	// metrics wrapper
	httpHandler = telemetry.NewRequestMetrics(httpHandler)

	// role/contextID wrapper
	if server.identityMapper != nil {
		httpHandler = identity.NewContextHandler(httpHandler, server.identityMapper)
	} else {
		httpHandler = identity.NewContextHandler(httpHandler, identity.GuestIdentityMapper)
	}

	// Add correlationID
	httpHandler = correlation.NewHandler(httpHandler)

	return httpHandler
}

// ServeHTTP should write reply headers and data to the ResponseWriter
// and then return. Returning signals that the request is finished; it
// is not valid to use the ResponseWriter or read from the
// Request.Body after or concurrently with the completion of the
// ServeHTTP call.
func (server *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	server.httpServer.Handler.ServeHTTP(w, r)
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	marshal.WriteJSON(w, r, httperror.NotFound("%s", r.URL.Path))
}

// GetServerURL returns the absolute URL for relativeEndpoint as seen by the
// client of request r. The scheme is taken from the X-Forwarded-Proto header
// when present (it is trusted as-is), otherwise from s.Protocol(); the host
// from r.URL.Host, then r.Host, then the server's host:port.
func GetServerURL(s Server, r *http.Request, relativeEndpoint string) *url.URL {
	proto := s.Protocol()

	// Allow upstream proxies  to specify the forwarded protocol. Allow this value
	// to override our own guess.
	if specifiedProto := r.Header.Get(header.XForwardedProto); specifiedProto != "" {
		proto = specifiedProto
	}

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = s.HostName() + ":" + s.Port()
	}

	return &url.URL{
		Scheme: proto,
		Host:   host,
		Path:   relativeEndpoint,
	}
}

// GetServerBaseURL returns scheme://host:port for the server's own bind
// address, without consulting any request headers.
func GetServerBaseURL(s Server) *url.URL {
	return &url.URL{
		Scheme: s.Protocol(),
		Host:   s.HostName() + ":" + s.Port(),
	}
}
