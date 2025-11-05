package streamctx

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

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
