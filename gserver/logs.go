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

func (e *Server) newLogUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		startTime := time.Now()
		resp, err := handler(ctx, req)
		defer func() {
			userAgent := headerFromContext(ctx, "user-agent")
			if err == nil && telemetry.ShouldSkip(e.cfg.SkipLogPaths, info.FullMethod, userAgent) {
				return
			}
			logRequest(ctx, info.FullMethod, userAgent, startTime, req, err)
		}()
		return resp, err
	}
}

func (e *Server) newLogStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		startTime := time.Now()
		err := handler(srv, ss)
		ctx := ss.Context()
		defer func() {
			userAgent := headerFromContext(ctx, "user-agent")
			if err == nil && telemetry.ShouldSkip(e.cfg.SkipLogPaths, info.FullMethod, userAgent) {
				return
			}
			logRequest(ctx, info.FullMethod, userAgent, startTime, srv, err)
		}()
		return err
	}
}

func logRequest(ctx context.Context, responseType, userAgent string, startTime time.Time, req any, err error) {
	duration := time.Since(startTime)
	expensiveRequest := duration > WarnUnaryRequestLatency

	idx := identity.FromContext(ctx)
	role := idx.Identity().Role()
	remote := idx.ClientIP()

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
		// Do not log client errors
		if code != codes.NotFound && code != codes.InvalidArgument && code != codes.Canceled && code != codes.PermissionDenied && code != codes.Unauthenticated {
			logError(ctx, code, responseType, err, cause)
		}
	}

	// Do not record metrics for 404 errors due to large number of DDoS requests
	switch code {
	case codes.NotFound:
		metricskey.GRPCReqByRole.IncrCounter(1, "unknown", "404", role)
	default:
		if expensiveRequest {
			logger.ContextKV(ctx, xlog.WARNING,
				"req", reflect.TypeOf(req),
				"res", responseType,
				"remote", remote,
				"ua", userAgent,
				"duration", duration.Milliseconds(),
				"code", code,
				"reason", "slow_request",
			)
		} else {
			logger.ContextKV(ctx, xlog.TRACE,
				"req", reflect.TypeOf(req),
				"res", responseType,
				"remote", remote,
				"ua", userAgent,
				"duration", duration.Milliseconds(),
				"code", code,
			)
		}
		codeName := code.String()
		metricskey.GRPCReqPerf.MeasureSince(startTime, responseType, codeName)
		metricskey.GRPCReqByRole.IncrCounter(1, responseType, codeName, role)
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
