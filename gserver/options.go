package gserver

import (
	"net/http"

	"google.golang.org/grpc"
)

// Middleware defines middleware handler
type Middleware func(handler http.Handler) http.Handler

// Option is an option that can be passed to New().
// Option configures how we set up the client
type Option interface {
	apply(*options)
}

// WithMiddleware option to provide HTTP handler
func WithMiddleware(otherHandler Middleware) Option {
	return newFuncOption(func(o *options) {
		o.handlers = append(o.handlers, otherHandler)
	})
}

// WithUnaryServerInterceptor option to provide RPC UnaryServerInterceptor
func WithUnaryServerInterceptor(other grpc.UnaryServerInterceptor) Option {
	return newFuncOption(func(o *options) {
		o.unary = append(o.unary, other)
	})
}

// WithStreamServerInterceptor option to provide RPC StreamServerInterceptor
func WithStreamServerInterceptor(other grpc.StreamServerInterceptor) Option {
	return newFuncOption(func(o *options) {
		o.stream = append(o.stream, other)
	})
}

// MaxRecvMsgSize sets the maximum message size that a client can send to the server.
func MaxRecvMsgSize(size int) Option {
	return newFuncOption(func(o *options) {
		o.maxRecvMsgSize = size
	})
}

// MaxSendMsgSize sets the maximum message size that a server can send to the client.
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
