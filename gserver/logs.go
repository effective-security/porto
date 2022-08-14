package gserver

import (
	"context"
	"reflect"
	"time"

	"github.com/effective-security/metrics"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	warnUnaryRequestLatency = 300 * time.Millisecond
)

var (
	keyForReqPerf       = []string{"grpc", "request", "perf"}
	keyForReqSuccessful = []string{"grpc", "request", "status", "successful"}
	keyForReqFailed     = []string{"grpc", "request", "status", "failed"}
)

func (s *Server) newLogUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()
		resp, err := handler(ctx, req)
		defer logRequest(ctx, info, startTime, req, resp, err)
		return resp, err
	}
}

func logRequest(ctx context.Context, info *grpc.UnaryServerInfo, startTime time.Time, req interface{}, resp interface{}, err error) {
	duration := time.Since(startTime)
	expensiveRequest := duration > warnUnaryRequestLatency

	remote := "no_remote_client_info"
	peerInfo, ok := peer.FromContext(ctx)
	if ok {
		remote = peerInfo.Addr.String()
	}
	responseType := info.FullMethod

	idx := identity.FromContext(ctx)
	role := idx.Identity().Role()

	var code codes.Code
	if err != nil {
		switch err.(type) { //_resp := err.(type) {
		/* TODO:
		case GRPCError:
			code = _resp.Code()
		case *GRPCError:
			code = _resp.Code()
		*/
		case error:
			if s, ok := status.FromError(err); ok {
				code = s.Code()
			} else {
				logger.KV(xlog.ERROR, "err", err.Error())
			}
		default:
			logger.KV(xlog.ERROR,
				"ctx", correlation.ID(ctx),
				"type", reflect.TypeOf(err),
				"err", err.Error())
		}
	}

	l := xlog.TRACE
	if logger.LevelAt(xlog.DEBUG) {
		l = xlog.DEBUG
	} else if expensiveRequest {
		l = xlog.WARNING
	}

	logger.KV(l,
		"req", reflect.TypeOf(req),
		"res", responseType,
		"remote", remote,
		"duration", duration.Milliseconds(),
		"code", code,
		"ctx", correlation.ID(ctx),
		"role", role,
		"user", idx.Identity().Subject(),
	)

	tags := []metrics.Tag{
		{Name: "method", Value: info.FullMethod},
		{Name: "role", Value: role},
		{Name: "status", Value: code.String()},
	}

	metrics.MeasureSince(keyForReqPerf, startTime, tags...)

	if code == codes.OK {
		metrics.IncrCounter(keyForReqSuccessful, 1, tags...)
	} else {
		metrics.IncrCounter(keyForReqFailed, 1, tags...)
	}
}

func newStreamInterceptor(s *Server) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		logger.KV(xlog.DEBUG, "method", info.FullMethod)
		return handler(srv, ss)
	}
}
