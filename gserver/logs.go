package gserver

import (
	"context"
	"reflect"
	"time"

	"github.com/effective-security/porto/metricskey"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	// WarnUnaryRequestLatency is the threshold for logging a warning for a slow unary request.
	WarnUnaryRequestLatency = 2 * time.Second
)

func headerFromContext(ctx context.Context, name string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		vals := md.Get(name)
		if len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func (s *Server) newLogUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()
		resp, err := handler(ctx, req)
		defer func() {
			if err == nil && telemetry.ShouldSkip(s.cfg.SkipLogPaths, info.FullMethod, headerFromContext(ctx, "user-agent")) {
				return
			}
			logRequest(ctx, info, startTime, req, resp, err)
		}()
		return resp, err
	}
}

func logRequest(ctx context.Context, info *grpc.UnaryServerInfo, startTime time.Time, req interface{}, _ interface{}, err error) {
	duration := time.Since(startTime)
	expensiveRequest := duration > WarnUnaryRequestLatency

	var remote string
	peerInfo, ok := peer.FromContext(ctx)
	if ok {
		remote = peerInfo.Addr.String()
	}

	userAgent := headerFromContext(ctx, "user-agent")
	responseType := info.FullMethod
	idx := identity.FromContext(ctx)
	role := idx.Identity().Role()

	var code codes.Code
	var cause error
	if err != nil {
		switch _resp := err.(type) {
		case *httperror.Error:
			code = _resp.RPCStatus
			cause = _resp.Cause()
		case *httperror.ManyError:
			code = _resp.RPCStatus
			cause = _resp.Cause()
		default:
			if s, ok := status.FromError(err); ok {
				code = s.Code()
			} else {
				code = codes.Internal
			}
		}
		logError(ctx, code, info.FullMethod, err, cause)
	}

	l := xlog.TRACE
	if expensiveRequest {
		l = xlog.WARNING
	}

	logger.ContextKV(ctx, l,
		"req", reflect.TypeOf(req),
		"res", responseType,
		"remote", remote,
		"ua", userAgent,
		"duration", duration.Milliseconds(),
		"code", code,
	)

	codeName := code.String()
	metricskey.GRPCReqPerf.MeasureSince(startTime, info.FullMethod, codeName)
	metricskey.GRPCReqByRole.IncrCounter(1, info.FullMethod, codeName, role)
}

func newStreamInterceptor(_ *Server) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		logger.KV(xlog.DEBUG, "method", info.FullMethod)
		return handler(srv, ss)
	}
}

func logError(ctx context.Context, code codes.Code, method string, err, cause error) {
	sv := xlog.WARNING
	typ := "API_ERROR"
	if code == codes.Unknown || code == codes.Internal || code == codes.Unavailable {
		sv = xlog.ERROR
		typ = "INTERNAL_ERROR"
	}

	if cause != nil {
		if sv == xlog.ERROR {
			// for ERROR log with stack
			logger.ContextKV(ctx, sv,
				"type", typ,
				"method", method,
				"code", code.String(),
				"err", cause)
		} else {
			logger.ContextKV(ctx, sv,
				"type", typ,
				"method", method,
				"code", code.String(),
				"err", cause.Error())
		}
	}

	logger.ContextKV(ctx, sv,
		"type", typ,
		"method", method,
		"code", code.String(),
		"err", err.Error(),
	)
}
