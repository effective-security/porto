package gserver

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/x/netutil"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
	"go.uber.org/dig"
	"google.golang.org/grpc"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto", "gserver")

// ServiceFactory builds a Service for the given server. The returned value is
// passed to dig.Container.Invoke, so it must be a function whose parameters are
// resolved from the container; the function itself should call GServer.AddService.
type ServiceFactory func(GServer) any

// Service is a named sub-service hosted by a Server. Services are created by a
// ServiceFactory and registered with GServer.AddService; a Service may
// additionally implement RouteRegistrator, GRPCRegistrator or StartSubcriber.
type Service interface {
	// Name returns the unique service name used as the key in GServer.Service.
	Name() string
	// Close releases the service resources; it is called by Server.Close before
	// the listeners are shut down.
	Close()
	// IsReady indicates that service is ready to serve its end-points
	IsReady() bool
}

// StartSubcriber is an optional interface a Service can implement to be
// notified once the server has started.
type StartSubcriber interface {
	// OnStarted is called when the server started and
	// is ready to serve requests
	OnStarted() error
}

// RouteRegistrator is an optional interface a Service implements to expose
// REST endpoints; it is invoked once per listener when the router is built.
type RouteRegistrator interface {
	// RegisterRoute adds the service HTTP handlers to the router.
	RegisterRoute(restserver.Router)
}

// GRPCRegistrator is an optional interface a Service implements to expose gRPC
// services; it is invoked once per gRPC server instance (secure and insecure).
type GRPCRegistrator interface {
	// RegisterGRPC registers the service implementation on the gRPC server.
	RegisterGRPC(*grpc.Server)
}

// GServer is the server handle passed to ServiceFactory functions and
// returned by Start. Services use it to register themselves and to query
// server state; it is safe for concurrent reads after Start returns.
type GServer interface {
	// Name returns server name
	Name() string
	// Configuration of the server
	Configuration() *Config
	// AddService to the server
	AddService(svc Service)
	// Service returns service by name
	Service(name string) Service
	// IsReady returns true when the server is ready to serve
	IsReady() bool
	// StartedAt returns Time when the server has started
	StartedAt() time.Time
	// ListenURLs is the list of URLs that the server listens on
	ListenURLs() []string
	// Hostname is the hostname
	Hostname() string
	// LocalIP is the local IP4
	LocalIP() string
	// Discovery returns Discovery interface
	Discovery() discovery.Discovery
	// Err returns error channel
	Err() <-chan error
	// Close gracefully shuts down all servers/listeners.
	// Client requests will be terminated with request timeout.
	// After timeout, enforce remaning requests be closed immediately.
	Close()
}

// Server is the GServer implementation returned by Start. It owns the
// listeners, the per-listener HTTP and gRPC servers, and the registered
// services. Use Start to construct it; the zero value is not usable.
type Server struct {
	// Listeners are the accepted network listeners, one per unique listen address.
	Listeners []net.Listener

	ipaddr   string
	hostname string
	// a map of contexts for the servers that serves client requests.
	sctxs map[string]*serveCtx

	di   *dig.Container
	name string
	cfg  Config

	stopc     chan struct{}
	errc      chan error
	closeOnce sync.Once
	startedAt time.Time

	services map[string]Service

	authz    *authz.Provider
	identity roles.IdentityProvider
	disco    discovery.Discovery

	opts options
}

// Start creates the services from serviceFactories, opens the listeners from
// cfg.ListenURLs and begins serving in background goroutines, returning the
// running server. The container must provide discovery.Discovery and, when
// cfg.IdentityMap enables JWT or DPoP, a jwt.Parser. On error any partially
// opened listeners are closed and the error is returned; on success the caller
// must eventually call Close. Serve errors are reported on Err.
func Start(
	name string,
	cfg *Config,
	container *dig.Container,
	serviceFactories map[string]ServiceFactory,
	opts ...Option,
) (GServer, error) {
	var e *Server
	var err error
	serving := false
	defer func() {
		// if no error, then do nothing
		if e == nil || err == nil {
			return
		}
		if !serving {
			// errored before starting gRPC server for serveCtx.serversC
			for _, sctx := range e.sctxs {
				close(sctx.serversC)
			}
		}
		e.Close()
		e = nil
	}()

	e, err = newServer(name, cfg, container, serviceFactories, opts...)
	if err != nil {
		return nil, err
	}

	err = container.Invoke(func(
		d discovery.Discovery,
	) error {
		e.disco = d
		return nil
	})
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to inject dependencies")
	}

	if cfg.IdentityMap != nil {
		var jwtparser jwt.Parser
		err = container.Invoke(func(jwtParser jwt.Parser) error {
			jwtparser = jwtParser
			return nil
		})
		if err != nil {
			logger.KV(xlog.ERROR, "reason", "jwt.Parser not provided", "err", err)
		}
		iden, err := roles.New(cfg.IdentityMap, jwtparser)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to create roles AuthZ")
		}
		e.identity = iden
	} else {
		iden, err := roles.New(&roles.IdentityMap{}, nil)
		if err != nil {
			logger.KV(xlog.ERROR, "err", err)
		}
		e.identity = iden
	}

	if cfg.Authz != nil &&
		(len(cfg.Authz.Allow) > 0 ||
			len(cfg.Authz.AllowAny) > 0 ||
			len(cfg.Authz.AllowAnyRole) > 0) {
		e.authz, err = authz.New(cfg.Authz)
		if err != nil {
			return nil, err
		}
	}

	if err = e.serveClients(); err != nil {
		return e, err
	}

	// Register services
	for _, svc := range e.services {
		_ = e.disco.Register(e.Name(), svc)
	}

	serving = true
	return e, nil
}

func newServer(
	name string,
	cfg *Config,
	container *dig.Container,
	serviceFactories map[string]ServiceFactory,
	opts ...Option,
) (*Server, error) {
	var err error

	ipaddr, err := netutil.GetLocalIP()
	if err != nil {
		ipaddr = "127.0.0.1"
		logger.KV(xlog.ERROR, "reason", "unable_determine_ipaddr", "use", ipaddr, "err", err.Error())
	}
	hostname, _ := os.Hostname()

	e := &Server{
		ipaddr:   ipaddr,
		hostname: hostname,
		name:     name,
		cfg:      *cfg,
		di:       container,
		services: make(map[string]Service),
		//sctxs: make(map[string]*serveCtx),
		stopc:     make(chan struct{}),
		startedAt: time.Now(),
	}

	for _, o := range opts {
		o.apply(&e.opts)
	}

	for _, svc := range cfg.Services {
		sf := serviceFactories[svc]
		if sf == nil {
			return nil, errors.Errorf("service factory is not registered: %q", svc)
		}
		err = container.Invoke(sf(e))
		if err != nil {
			return nil, errors.WithMessagef(err, "service factory failed, server=%q, service=%s",
				name, svc)
		}
	}

	logger.KV(xlog.TRACE, "status", "configuring_listeners", "server", name)

	e.sctxs, err = configureListeners(cfg)
	if err != nil {
		return e, err
	}

	for _, sctx := range e.sctxs {
		e.Listeners = append(e.Listeners, sctx.listener)
	}

	// buffer channel so goroutines on closed connections won't wait forever
	e.errc = make(chan error, len(e.Listeners)+2*len(e.sctxs))

	return e, nil
}

func (e *Server) serveClients() (err error) {
	// start client servers in each goroutine
	for _, sctx := range e.sctxs {
		go func(s *serveCtx) {
			e.errHandler(s.serve(e, e.errHandler))
		}(sctx)
	}
	return nil
}

func (e *Server) errHandler(err error) {
	if err != nil && !strings.Contains(err.Error(), "closed") {
		logger.KV(xlog.INFO, "err", err)
	}
	select {
	case <-e.stopc:
		return
	default:
	}
	select {
	case <-e.stopc:
	case e.errc <- err:
	}
}

// Close gracefully shuts down all servers/listeners.
// Client requests will be terminated with request timeout.
// After timeout, enforce remaning requests be closed immediately.
func (e *Server) Close() {
	logger.KV(xlog.INFO, "server", e.Name())

	for _, svc := range e.services {
		svc.Close()
	}

	e.closeOnce.Do(func() { close(e.stopc) })

	// close client requests with request timeout
	timeout := 3 * time.Second
	if e.cfg.Timeout.Request != 0 {
		timeout = e.cfg.Timeout.Request
	}
	for _, sctx := range e.sctxs {
		for ss := range sctx.serversC {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			stopServers(ctx, ss)
			cancel()
		}
	}

	for _, sctx := range e.sctxs {
		sctx.cancel()
	}

	for i := range e.Listeners {
		if e.Listeners[i] != nil {
			e.Listeners[i].Close()
		}
	}
}

func stopServers(ctx context.Context, ss *servers) {
	shutdownNow := func() {
		// first, close the http.Server
		_ = ss.http.Shutdown(ctx)
		// then close grpc.Server; cancels all active RPCs
		ss.grpc.Stop()
	}

	// do not grpc.Server.GracefulStop with TLS enabled server
	// See https://github.com/grpc/grpc-go/issues/1384#issuecomment-317124531
	if ss.secure {
		shutdownNow()
		return
	}

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		// close listeners to stop accepting new connections,
		// will block on any existing transports
		ss.grpc.GracefulStop()
	}()

	// wait until all pending RPCs are finished
	select {
	case <-ch:
	case <-ctx.Done():
		// took too long, manually close open transports
		// e.g. watch streams
		shutdownNow()

		// concurrent GracefulStop should be interrupted
		<-ch
	}
}

// Err returns the channel on which listener/serve errors are reported. The
// channel is buffered and is never closed; errors are dropped once Close begins.
func (e *Server) Err() <-chan error { return e.errc }

// Name returns server name
func (e *Server) Name() string {
	return e.name
}

// Configuration returns a pointer to the server's copy of the Config;
// mutating it after Start has no effect on already configured listeners.
func (e *Server) Configuration() *Config {
	return &e.cfg
}

// AddService registers svc by its Name, replacing any service with the same
// name. It must be called from a ServiceFactory, before Start begins serving;
// the services map is not synchronized.
func (e *Server) AddService(svc Service) {
	logger.KV(xlog.NOTICE, "server", e.Name(), "service", svc.Name())

	e.services[svc.Name()] = svc
}

// Service returns the registered service with the given name, or nil.
func (e *Server) Service(name string) Service {
	return e.services[name]
}

// IsReady returns true when every registered service reports IsReady.
func (e *Server) IsReady() bool {
	for _, ss := range e.services {
		if !ss.IsReady() {
			logger.KV(xlog.INFO, "status", "NOT_READY", "svc", ss.Name())
			return false
		}
	}
	return true
}

// StartedAt returns Time when the server has started
func (e *Server) StartedAt() time.Time {
	return e.startedAt
}

// ListenURLs returns the configured Config.ListenURLs (not the resolved
// listener addresses).
func (e *Server) ListenURLs() []string {
	return e.cfg.ListenURLs
}

// Hostname is the hostname
func (e *Server) Hostname() string {
	return e.hostname
}

// LocalIP returns the local IPv4 address detected at startup, or 127.0.0.1
// when it could not be determined.
func (e *Server) LocalIP() string {
	return e.ipaddr
}

// Discovery returns the discovery.Discovery injected from the container; all
// services are registered with it under the server name after Start.
func (e *Server) Discovery() discovery.Discovery {
	return e.disco
}
