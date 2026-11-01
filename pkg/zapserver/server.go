// Package zapserver provides a high-performance ZAP-native server adapter for Porto,
// built on the zip framework (fasthttp + Fiber v3 + zero-copy ZAP wire).
package zapserver

import (
	"context"
	"fmt"
	"sync"

	"github.com/effective-security/porto/restserver"
	"github.com/zap-proto/zip"
)

// Config configures the ZAP-native zip server.
type Config struct {
	AppName    string   `json:"app_name" yaml:"app_name"`
	ListenAddr string   `json:"listen_addr" yaml:"listen_addr"`
	ExtraAddrs []string `json:"extra_addrs" yaml:"extra_addrs"`
}

// Server wraps a zip.App to host Porto services over ZAP native RPC and fasthttp.
type Server struct {
	cfg      Config
	app      *zip.App
	services map[string]restserver.Service
	mu       sync.RWMutex
	running  bool
}

// New creates a new zapserver instance.
func New(cfg Config) *Server {
	if cfg.AppName == "" {
		cfg.AppName = "porto-zap"
	}
	app := zip.New(zip.Config{
		AppName: cfg.AppName,
	})

	return &Server{
		cfg:      cfg,
		app:      app,
		services: make(map[string]restserver.Service),
	}
}

// App returns the underlying zip.App.
func (s *Server) App() *zip.App {
	return s.app
}

// AddService registers a Porto restserver.Service with the zapserver.
func (s *Server) AddService(svc restserver.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.services[svc.Name()] = svc
}

// RegisterOperation binds a typed operation with generic input and output.
// It automatically exposes the operation across REST, ZAP RPC, and MCP tools.
func RegisterOperation[I, O any](s *Server, path string, fn func(context.Context, *I) (*O, error)) {
	zip.Post(s.app, path, fn)
}

// RegisterGet binds a typed GET operation with generic input and output.
func RegisterGet[I, O any](s *Server, path string, fn func(context.Context, *I) (*O, error)) {
	zip.Get(s.app, path, fn)
}

// Start boots the server listeners.
func (s *Server) Start() error {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	addr := s.cfg.ListenAddr
	if addr == "" {
		addr = ":9653"
	}

	addrs := append([]string{addr}, s.cfg.ExtraAddrs...)
	return s.app.Listen(addrs...)
}

// Close gracefully shuts down the server and all registered services.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, svc := range s.services {
		svc.Close()
	}
	s.running = false
	return s.app.Shutdown()
}

// IsReady returns true if all registered services report ready.
func (s *Server) IsReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, svc := range s.services {
		if !svc.IsReady() {
			return false
		}
	}
	return true
}

// String returns a human-readable identifier.
func (s *Server) String() string {
	return fmt.Sprintf("zapserver[%s]", s.cfg.AppName)
}
