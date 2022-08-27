package restserver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/porto/restserver/ready"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/x/netutil"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto", "rest")

// MaxRequestSize specifies max size of regular HTTP Post requests in bytes, 64 Mb
const MaxRequestSize = 64 * 1024 * 1024

const (
	// EvtSourceStatus specifies source for service Status
	EvtSourceStatus = "status"
	// EvtServiceStarted specifies Service Started event
	EvtServiceStarted = "service started"
	// EvtServiceStopped specifies Service Stopped event
	EvtServiceStopped = "service stopped"
)

// ServerEvent specifies server event type
type ServerEvent int

const (
	// ServerStartedEvent is fired on server start
	ServerStartedEvent ServerEvent = iota
	// ServerStoppedEvent is fired after server stopped
	ServerStoppedEvent
	// ServerStoppingEvent is fired before server stopped
	ServerStoppingEvent
)

// ServerEventFunc is a callback to handle server events
type ServerEventFunc func(evt ServerEvent)

// Server is an interface to provide server status
type Server interface {
	http.Handler
	Name() string
	Version() string
	HostName() string
	LocalIP() string
	Port() string
	Protocol() string
	PublicURL() string
	StartedAt() time.Time
	Service(name string) Service
	Config() Config
	TLSConfig() *tls.Config

	// IsReady indicates that all subservices are ready to serve
	IsReady() bool

	AddService(s Service)
	StartHTTP() error
	StopHTTP()

	OnEvent(evt ServerEvent, handler ServerEventFunc)
}

// MuxFactory creates http handlers.
type MuxFactory interface {
	NewMux() http.Handler
}

// HTTPServer is responsible for exposing the collection of the services
// as a single HTTP server
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
	serving         bool
	startedAt       time.Time
	clientAuth      string
	services        map[string]Service
	evtHandlers     map[ServerEvent][]ServerEventFunc
	lock            sync.RWMutex
	shutdownTimeout time.Duration
}

// New creates a new instance of the server
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
			logger.Errorf("reason=unable_determine_ipaddr, use=%q, err=[%+v]", ipaddr, err)
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

// WithAuthz enables to use Authz
func (server *HTTPServer) WithAuthz(authz authz.HTTPAuthz) *HTTPServer {
	server.authz = authz
	return server
}

// WithIdentityProvider enables to set idenity on each request
func (server *HTTPServer) WithIdentityProvider(provider identity.ProviderFromRequest) *HTTPServer {
	server.identityMapper = provider
	return server
}

// WithCORS enables CORS options
func (server *HTTPServer) WithCORS(cors *CORSOptions) *HTTPServer {
	server.cors = cors
	return server
}

// WithShutdownTimeout sets the connection draining timeouts on server shutdown
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

// AddService provides a service registration for the server
func (server *HTTPServer) AddService(s Service) {
	server.lock.Lock()
	defer server.lock.Unlock()
	if server.services[s.Name()] != nil {
		logger.Panicf("service already registered: %s", s.Name())
	}
	server.services[s.Name()] = s
}

// OnEvent accepts a callback to handle server events
func (server *HTTPServer) OnEvent(evt ServerEvent, handler ServerEventFunc) {
	server.lock.Lock()
	defer server.lock.Unlock()

	server.evtHandlers[evt] = append(server.evtHandlers[evt], handler)
}

// Service returns a registered server
func (server *HTTPServer) Service(name string) Service {
	server.lock.Lock()
	defer server.lock.Unlock()
	return server.services[name]
}

// HostName returns the host name of the server
func (server *HTTPServer) HostName() string {
	return server.hostname
}

// Port returns the port name of the server
func (server *HTTPServer) Port() string {
	return server.port
}

// Protocol returns the protocol
func (server *HTTPServer) Protocol() string {
	if server.tlsConfig != nil {
		return "https"
	}
	return "http"
}

// LocalIP returns the IP address of the server
func (server *HTTPServer) LocalIP() string {
	return server.ipaddr
}

// PublicURL returns the public URL of the server
func (server *HTTPServer) PublicURL() string {
	return server.httpConfig.GetPublicURL()
}

// StartedAt returns the time when the server started
func (server *HTTPServer) StartedAt() time.Time {
	return server.startedAt
}

// Uptime returns the duration the server was up
func (server *HTTPServer) Uptime() time.Duration {
	return time.Now().UTC().Sub(server.startedAt)
}

// Version returns the version of the server
func (server *HTTPServer) Version() string {
	return server.version
}

// Name returns the server name
func (server *HTTPServer) Name() string {
	return server.httpConfig.GetServerName()
}

// HTTPConfig returns HTTPServerConfig
func (server *HTTPServer) HTTPConfig() Config {
	return server.httpConfig
}

// TLSConfig returns TLSConfig
func (server *HTTPServer) TLSConfig() *tls.Config {
	return server.tlsConfig
}

// IsReady returns true when the server is ready to serve
func (server *HTTPServer) IsReady() bool {
	if !server.serving {
		return false
	}
	for _, ss := range server.services {
		if !ss.IsReady() {
			return false
		}
	}
	return true
}

// WithMuxFactory requires the server to use `muxFactory` to create server handler.
func (server *HTTPServer) WithMuxFactory(muxFactory MuxFactory) {
	server.muxFactory = muxFactory
}

func (server *HTTPServer) broadcast(evt ServerEvent) {
	for _, handler := range server.evtHandlers[evt] {
		handler(evt)
	}
}

// StartHTTP will verify all the TLS related files are present and start the actual HTTPS listener for the server
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
		server.serving = true
		if httpsListener != nil {
			return server.httpServer.Serve(httpsListener)
		}
		return server.httpServer.ListenAndServe()
	}

	go func() {
		server.broadcast(ServerStartedEvent)

		logger.Infof("server=%s, bind=%v, status=starting, protocol=%s",
			server.Name(), bindAddr, server.Protocol())

		// this is a blocking call to serve
		if err := serve(); err != nil {
			server.serving = false
			// panic, only if not Serve error while stopping the server,
			// which is a valid error
			if netutil.IsAddrInUse(err) || err != http.ErrServerClosed {
				logger.Panicf("server=%s, err=[%v]", server.Name(), errors.WithStack(err))
			}
			logger.Warningf("server=%s, status=stopped, reason=[%s]", server.Name(), err.Error())
		}
	}()

	return nil
}

// StopHTTP will perform a graceful shutdown of the serivce by
//  1. signally to the Load Balancer to remove this instance from the pool
//     by changing to response to /availability
//  2. cause new responses to have their Connection closed when finished
//     to force clients to re-connect [hopefully to a different instance]
//  3. wait the minShutdownTime to ensure the LB has noticed the status change
//  4. wait for existing requests to finish processing
//  5. step 4 is capped by a overrall timeout where we'll give up waiting
//     for the requests to complete and will exit.
//
// it is expected that you don't try and use the server instance again
// after this. [i.e. if you want to start it again, create another server instance]
func (server *HTTPServer) StopHTTP() {
	server.broadcast(ServerStoppingEvent)

	// close services
	for _, f := range server.services {
		logger.Tracef("service=%q, status=closing", f.Name())
		f.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), server.shutdownTimeout)
	defer cancel()
	err := server.httpServer.Shutdown(ctx)
	if err != nil {
		logger.Errorf("reason=Shutdown, err=[%+v]", err)
	}
	server.broadcast(ServerStoppedEvent)
}

// NewMux creates a new http handler for the http server, typically you only
// need to call this directly for tests.
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
	logger.Debugf("server=%s, service_count=%d",
		server.Name(), len(server.services))

	var err error
	httpHandler := router.Handler()

	logger.Infof("server=%s, ClientAuth=%s", server.Name(), server.clientAuth)

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
	marshal.WriteJSON(w, r, httperror.NotFound(r.URL.Path))
}

// GetServerURL returns complete server URL for given relative end-point
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

// GetServerBaseURL returns server base URL
func GetServerBaseURL(s Server) *url.URL {
	return &url.URL{
		Scheme: s.Protocol(),
		Host:   s.HostName() + ":" + s.Port(),
	}
}
