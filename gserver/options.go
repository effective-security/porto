package gserver

import (
	"net/http"

	"google.golang.org/grpc"
)

// Middleware wraps an http.Handler; it is applied by WithMiddleware.
type Middleware func(handler http.Handler) http.Handler

// Option customizes a Server created by Start.
type Option interface {
	apply(*options)
}

// WithMiddleware adds an HTTP middleware to the REST handler chain. It runs
// after the built-in middlewares (identity, authz, logging), closest to the
// router; multiple middlewares wrap in the order given.
func WithMiddleware(otherHandler Middleware) Option {
	return newFuncOption(func(o *options) {
		o.handlers = append(o.handlers, otherHandler)
	})
}

// WithUnaryServerInterceptor appends a gRPC unary interceptor after the
// built-in chain (panic recovery, validation, correlation, logging, identity, authz).
func WithUnaryServerInterceptor(other grpc.UnaryServerInterceptor) Option {
	return newFuncOption(func(o *options) {
		o.unary = append(o.unary, other)
	})
}

// WithStreamServerInterceptor appends a gRPC stream interceptor after the
// built-in chain (logging, correlation, identity, authz).
func WithStreamServerInterceptor(other grpc.StreamServerInterceptor) Option {
	return newFuncOption(func(o *options) {
		o.stream = append(o.stream, other)
	})
}

// MaxRecvMsgSize sets the maximum gRPC message size a client can send,
// overriding Config.MaxRecvMsgSize.
func MaxRecvMsgSize(size int) Option {
	return newFuncOption(func(o *options) {
		o.maxRecvMsgSize = size
	})
}

// MaxSendMsgSize sets the maximum gRPC message size the server can send,
// overriding Config.MaxSendMsgSize.
func MaxSendMsgSize(size int) Option {
	return newFuncOption(func(o *options) {
		o.maxSendMsgSize = size
	})
}

type options struct {
	handlers       []Middleware
	unary          []grpc.UnaryServerInterceptor
	stream         []grpc.StreamServerInterceptor
	maxRecvMsgSize int
	maxSendMsgSize int
}

type funcOption struct {
	f func(*options)
}

func (fo *funcOption) apply(o *options) {
	fo.f(o)
}

func newFuncOption(f func(*options)) *funcOption {
	return &funcOption{
		f: f,
	}
}
