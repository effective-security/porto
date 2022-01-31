package gserver

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/porto/x/netutil"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
	"github.com/pkg/errors"
	"go.uber.org/dig"
	"google.golang.org/grpc"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto", "gserver")

// ServiceFactory is interface to create Services
type ServiceFactory func(*Server) interface{}

// Service provides a way for subservices to be registered so they get added to the http API.
type Service interface {
	Name() string
	Close()
	// IsReady indicates that service is ready to serve its end-points
	IsReady() bool
}

// StartSubcriber provides
type StartSubcriber interface {
	// OnStarted is called when the server started and
	// is ready to serve requests
	OnStarted() error
}

// RouteRegistrator provides interface to register HTTP route
type RouteRegistrator interface {
	RegisterRoute(restserver.Router)
}

// GRPCRegistrator provides interface to register gRPC service
type GRPCRegistrator interface {
	RegisterGRPC(*grpc.Server)
}

// Server contains a running server and its listeners.
type Server struct {
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
}

// Start returns running Server
func Start(
	name string,
	cfg *Config,
	container *dig.Container,
	serviceFactories map[string]ServiceFactory,
) (e *Server, err error) {
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

	e, err = newServer(name, cfg, container, serviceFactories)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	err = container.Invoke(func(
		d discovery.Discovery,
		jwtParser jwt.Parser) error {
		e.disco = d
		iden, err := roles.New(&cfg.IdentityMap, jwtParser)
		if err != nil {
			logger.Errorf("err=[%+v]", err)
			return err
		}

		e.identity = iden

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if cfg.Authz != nil &&
		(len(cfg.Authz.Allow) > 0 ||
			len(cfg.Authz.AllowAny) > 0 ||
			len(cfg.Authz.AllowAnyRole) > 0) {
		e.authz, err = authz.New(cfg.Authz)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if err = e.serveClients(); err != nil {
		return e, err
	}

	// Register services
	for _, svc := range e.services {
		e.disco.Register(e.Name(), svc)
	}

	serving = true
	return e, nil
}

func newServer(
	name string,
	cfg *Config,
	container *dig.Container,
	serviceFactories map[string]ServiceFactory,
) (*Server, error) {
	var err error

	ipaddr, err := netutil.GetLocalIP()
	if err != nil {
		ipaddr = "127.0.0.1"
		logger.Errorf("reason=unable_determine_ipaddr, use=%q, err=[%+v]", ipaddr, err)
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

	for _, svc := range cfg.Services {
		sf := serviceFactories[svc]
		if sf == nil {
			return nil, errors.Errorf("service factory is not registered: %q", svc)
		}
		err = container.Invoke(sf(e))
		if err != nil {
			return nil, errors.WithMessagef(err, "reason=factory, server=%q, service=%s",
				name, svc)
		}
	}

	logger.Tracef("status=configuring_listeners, server=%s", name)

	e.sctxs, err = configureListeners(cfg)
	if err != nil {
		return e, errors.WithStack(err)
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
		logger.Infof("err=[%v]", err)
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
	logger.Infof("server=%s", e.Name())

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
		ss.http.Shutdown(ctx)
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

// Err returns error channel
func (e *Server) Err() <-chan error { return e.errc }

// Name returns server name
func (e *Server) Name() string {
	return e.name
}

// Configuration of the server
func (e *Server) Configuration() *Config {
	return &e.cfg
}

// AddService to the server
func (e *Server) AddService(svc Service) {
	logger.Noticef("server=%s, service=%s",
		e.Name(), svc.Name())

	e.services[svc.Name()] = svc
}

// Service returns service by name
func (e *Server) Service(name string) Service {
	return e.services[name]
}

// IsReady returns true when the server is ready to serve
func (e *Server) IsReady() bool {
	for _, ss := range e.services {
		if !ss.IsReady() {
			logger.Infof("status=NOT_READY, svc=%s", ss.Name())
			return false
		}
	}
	return true
}

// StartedAt returns Time when the server has started
func (e *Server) StartedAt() time.Time {
	return e.startedAt
}

// ListenURLs is the list of URLs that the server listens on
func (e *Server) ListenURLs() []string {
	return e.cfg.ListenURLs
}

// Hostname is the hostname
func (e *Server) Hostname() string {
	return e.hostname
}

// LocalIP is the local IP4
func (e *Server) LocalIP() string {
	return e.ipaddr
}

// Discovery returns Discovery interface
func (e *Server) Discovery() discovery.Discovery {
	return e.disco
}
