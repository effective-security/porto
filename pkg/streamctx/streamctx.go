package streamctx

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// WithContext returns a grpc.ServerStream whose Context method returns ctx.
// If ss was already produced by WithContext, its context is replaced in place
// and the same stream is returned (so earlier holders of that stream observe
// the new context); otherwise ss is wrapped.
func WithContext(ctx context.Context, ss grpc.ServerStream) grpc.ServerStream {
	if sss, ok := ss.(*serverStream); ok {
		sss.ctx = ctx
		return sss
	}

	return &serverStream{
		ServerStream: ss,
		ctx:          ctx,
	}
}

// serverStream overrides Context on an embedded grpc.ServerStream.
type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context {
	return s.ctx
}
func (s *serverStream) SetHeader(md metadata.MD) error {
	return s.ServerStream.SetHeader(md)
}
func (s *serverStream) SendHeader(md metadata.MD) error {
	return s.ServerStream.SendHeader(md)
}
func (s *serverStream) SetTrailer(md metadata.MD) {
	s.ServerStream.SetTrailer(md)
}
func (s *serverStream) SendMsg(m any) error {
	return s.ServerStream.SendMsg(m)
}
func (s *serverStream) RecvMsg(m any) error {
	return s.ServerStream.RecvMsg(m)
}
