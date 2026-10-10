package gserver

import (
	"cmp"
	"context"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/effective-security/porto/metricskey"
	"github.com/effective-security/porto/pkg/streamctx"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	// WarnUnaryRequestLatency is the duration above which a gRPC request
	// (unary or stream) is logged at WARNING level as slow_request. It is a
	// process-global setting read on every request.
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

type callLogKey struct{}

// callLog carries the caller of one gRPC call from the identity
// interceptor back to the log interceptor, which runs before it: the log
// interceptor puts a callLog in the call context and the identity handoff
// interceptor, right after identity, stores the RequestContext in it. The
// pointer is atomic so that the log interceptor's read stays safe if an
// interceptor runs the rest of the chain on another goroutine.
type callLog struct {
	caller atomic.Pointer[identity.RequestContext]
}

// withCallLog returns ctx with a new callLog for the call.
func withCallLog(ctx context.Context) (context.Context, *callLog) {
	call := &callLog{}
	return context.WithValue(ctx, callLogKey{}, call), call
}

// recordCaller stores the RequestContext in ctx in the callLog of the call,
// if the log interceptor created one.
func recordCaller(ctx context.Context) {
	if call, ok := ctx.Value(callLogKey{}).(*callLog); ok {
		call.caller.Store(identity.FromContext(ctx))
	}
}

// identityHandoffUnaryInterceptor runs right after
// identity.NewAuthUnaryInterceptor and passes the caller to the log
// interceptor; see callLog.
func identityHandoffUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		recordCaller(ctx)
		return handler(ctx, req)
	}
}

// identityHandoffStreamInterceptor is the streaming counterpart of
// identityHandoffUnaryInterceptor.
func identityHandoffStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		recordCaller(ss.Context())
		return handler(srv, ss)
	}
}

// callerOf returns the role and client IP of the call: those of the
// RequestContext stored in call, or, for a call rejected before or by
// identity (rate limit, validation, identity errors), the guest role and
// the client IP resolved under the server's trusted proxy policy.
func (e *Server) callerOf(ctx context.Context, call *callLog) (role, remote string) {
	if rc := call.caller.Load(); rc != nil {
		return rc.Identity().Role(), rc.ClientIP()
	}
	if e.trustedProxies != nil {
		ctx = identity.WithTrustedProxies(ctx, e.trustedProxies)
	}
	return identity.GuestRoleName, identity.ClientIPFromGRPC(ctx)
}

func (e *Server) newLogUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		startTime := time.Now()
		ctx, call := withCallLog(ctx)
		resp, err := handler(ctx, req)
		defer func() {
			// SkipLogPaths matches the User-Agent as sent, so a call without
			// one is skipped only by an empty or "*" agent
			userAgent := headerFromContext(ctx, header.UserAgent)
			if err == nil && telemetry.ShouldSkip(e.cfg.SkipLogPaths, info.FullMethod, userAgent) {
				return
			}
			role, remote := e.callerOf(ctx, call)
			logRequest(ctx, info.FullMethod, role, remote, cmp.Or(userAgent, telemetry.NoAgent), startTime, req, err)
		}()
		return resp, err
	}
}

func (e *Server) newLogStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		startTime := time.Now()
		ctx, call := withCallLog(ss.Context())
		err := handler(srv, streamctx.WithContext(ctx, ss))
		defer func() {
			userAgent := headerFromContext(ctx, header.UserAgent)
			if err == nil && telemetry.ShouldSkip(e.cfg.SkipLogPaths, info.FullMethod, userAgent) {
				return
			}
			role, remote := e.callerOf(ctx, call)
			logRequest(ctx, info.FullMethod, role, remote, cmp.Or(userAgent, telemetry.NoAgent), startTime, srv, err)
		}()
		return err
	}
}

// logRequest logs one gRPC call and records its metrics. remote is the
// client IP and agent the User-Agent (telemetry.NoAgent when missing),
// under the field names of the REST request logger; error lines carry
// remote too.
func logRequest(ctx context.Context, responseType, role, remote, agent string, startTime time.Time, req any, err error) {
	duration := time.Since(startTime)
	expensiveRequest := duration > WarnUnaryRequestLatency

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
				// FINDINGS P-098: grpc-go sends such errors as Unknown.
				code = codes.Internal
			}
		}
		// Do not log client errors
		if code != codes.NotFound && code != codes.Canceled && code != codes.PermissionDenied && code != codes.Unauthenticated {
			logError(ctx, code, responseType, remote, err, cause)
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
				"agent", agent,
				"duration", duration.Milliseconds(),
				"code", code,
				"reason", "slow_request",
			)
		} else {
			logger.ContextKV(ctx, xlog.TRACE,
				"req", reflect.TypeOf(req),
				"res", responseType,
				"remote", remote,
				"agent", agent,
				"duration", duration.Milliseconds(),
				"code", code,
			)
		}
		codeName := code.String()
		metricskey.GRPCReqPerf.MeasureSince(startTime, responseType, codeName)
		metricskey.GRPCReqByRole.IncrCounter(1, responseType, codeName, role)
	}
}

func logError(ctx context.Context, code codes.Code, method, remote string, err, cause error) {
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
				"remote", remote,
				"code", code.String(),
				"err", err.Error(),
				"cause", cause)
		} else {
			logger.ContextKV(ctx, sv,
				"type", typ,
				"method", method,
				"remote", remote,
				"code", code.String(),
				"err", err.Error(),
				"cause", cause.Error(),
			)
		}
	} else {
		logger.ContextKV(ctx, sv,
			"type", typ,
			"method", method,
			"remote", remote,
			"code", code.String(),
			"err", err.Error(),
		)
	}
}
