package correlation

import (
	"context"
	"errors"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/effective-security/porto/pkg/streamctx"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/xhttp", "correlation")

// CorrelationIDgRPCHeaderName is the gRPC metadata key used to carry the
// correlation ID on outgoing calls and read it on incoming ones. It is a
// process-global that may be changed at startup, before any traffic.
var CorrelationIDgRPCHeaderName = "x-correlation-id"

const requestIDgRPCHeaderName = "x-request-id"

type contextKey int

const (
	keyContext contextKey = iota
	keyCorrelation
)

// IDSize is the length in characters of generated correlation IDs; incoming
// IDs longer than this are truncated.
const IDSize = 12

// Correlator is implemented by values (such as httperror.Error) that carry a
// correlation ID.
type Correlator interface {
	// CorrelationID returns the correlation ID, or "" when unknown.
	CorrelationID() string
}

// RequestContext is the value stored in the context by this package; it
// holds the request ID, aka Request-ID or Correlation-ID (for cross system
// request correlation). Retrieve it with Value or ID.
type RequestContext struct {
	// ID is the correlation ID.
	ID string
}

// NewHandler returns middleware that reads the correlation ID from the
// X-Correlation-ID or X-Request-ID request header (or generates one), stores
// it in the request context, adds it to the xlog context as "ctx" and sets
// the X-Correlation-ID response header before calling delegate. An ID
// already present in the context is reused.
func NewHandler(delegate http.Handler) http.Handler {
	h := func(w http.ResponseWriter, r *http.Request) {
		var rctx *RequestContext
		ctx := r.Context()
		v := ctx.Value(keyContext)
		if v == nil {
			rctx = &RequestContext{
				ID: correlationID(r),
			}
			r = r.WithContext(context.WithValue(ctx, keyContext, rctx))
		} else {
			rctx = v.(*RequestContext)
		}

		// add correlationID to logs as "ctx"
		r = r.WithContext(xlog.ContextWithKV(r.Context(), "ctx", rctx.ID))

		w.Header().Set(header.XCorrelationID, rctx.ID)
		delegate.ServeHTTP(w, r)
	}
	return http.HandlerFunc(h)
}

// NewAuthUnaryInterceptor returns a grpc.UnaryServerInterceptor that adds the
// correlation ID (from incoming metadata or newly generated) to the context
// and xlog fields, and recovers panics from the handler, logging them and
// returning an "unhandled exception" error.
func NewAuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, si *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (res any, err error) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.ContextKV(ctx, xlog.ERROR,
					"reason", "panic",
					"action", si.FullMethod,
					"err", rec,
					"stack", string(debug.Stack()))
				// FINDINGS P-098: a plain error reaches the client as Unknown.
				err = errors.New("unhandled exception")
			}
		}()

		var rctx *RequestContext
		v := ctx.Value(keyContext)
		if v == nil {
			rctx = &RequestContext{
				ID: correlationIDFromGRPC(ctx),
			}
			ctx = context.WithValue(ctx, keyContext, rctx)
		} else {
			rctx = v.(*RequestContext)
		}
		// add correlationID to logs as "ctx"
		ctx = xlog.ContextWithKV(ctx, "ctx", rctx.ID)

		return handler(ctx, req)
	}
}

// NewStreamServerInterceptor returns the streaming counterpart of
// NewAuthUnaryInterceptor; the stream is wrapped with streamctx.WithContext
// so handlers see the enriched context.
func NewStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		ctx := ss.Context()
		defer func() {
			if rec := recover(); rec != nil {
				logger.ContextKV(ctx, xlog.ERROR,
					"reason", "panic",
					"action", info.FullMethod,
					"err", rec,
					"stack", string(debug.Stack()))
				// FINDINGS P-098: a plain error reaches the client as Unknown.
				err = errors.New("unhandled exception")
			}
		}()

		var rctx *RequestContext
		v := ctx.Value(keyContext)
		if v == nil {
			rctx = &RequestContext{
				ID: correlationIDFromGRPC(ctx),
			}
			ctx = context.WithValue(ctx, keyContext, rctx)
		} else {
			rctx = v.(*RequestContext)
		}
		// add correlationID to logs as "ctx"
		ctx = xlog.ContextWithKV(ctx, "ctx", rctx.ID)

		// Wrap with Context
		ss = streamctx.WithContext(ctx, ss)

		return handler(srv, ss)
	}
}

// correlationIDFromGRPC will find or create a requestID for this request.
func correlationIDFromGRPC(ctx context.Context) string {
	corID := ID(ctx)
	if corID == "" {
		incomingID := ""
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			xid := md.Get(CorrelationIDgRPCHeaderName)
			if len(xid) == 0 {
				xid = md.Get(requestIDgRPCHeaderName)
			}
			if len(xid) == 0 {
				xid = md.Get(header.XCorrelationID)
			}
			if len(xid) > 0 {
				incomingID = xid[0]
			}
		}
		if incomingID != "" {
			corID = slices.StringUpto(incomingID, IDSize)
		} else {
			corID = certutil.RandomString(IDSize)
		}
		logger.ContextKV(ctx, xlog.DEBUG, "ctx", corID, "incoming_ctx", incomingID)
	}
	return corID
}

// correlationID will find or create a requestID for this http request.
func correlationID(req *http.Request) string {
	// 8 chars will have enough entropy
	// to correlate requests,
	// without the large footprint in the logs
	corID := ID(req.Context())
	if corID == "" {
		incomingID := req.Header.Get(header.XCorrelationID)
		if incomingID == "" {
			incomingID = req.Header.Get("X-Request-ID")
		}

		if incomingID != "" {
			corID = slices.StringUpto(incomingID, IDSize)
		} else {
			corID = certutil.RandomString(IDSize)
		}

		path := ""
		if req.URL != nil {
			path = req.URL.Path
		}
		l := xlog.DEBUG
		if strings.Contains(req.Header.Get(header.Accept), "json") {
			l = xlog.TRACE
		}
		logger.KV(l, "ctx", corID, "incoming_ctx", incomingID, "path", path)
	}
	return corID
}

// Value returns the RequestContext stored in ctx, or nil if none.
func Value(ctx context.Context) *RequestContext {
	v := ctx.Value(keyContext)
	if r, ok := v.(*RequestContext); ok {
		return r
	}
	return nil
}

// ID returns the correlation ID stored in ctx, or "" if none.
func ID(ctx context.Context) string {
	corID := ""
	v := Value(ctx)
	if v != nil {
		corID = v.ID
	}
	return corID
}

// WithID returns a context carrying a newly generated correlation ID (also
// added to the xlog fields). If ctx already has one, ctx is returned as is.
func WithID(ctx context.Context) context.Context {
	v := ctx.Value(keyContext)
	if v == nil {
		rctx := &RequestContext{
			ID: certutil.RandomString(IDSize),
		}
		ctx = context.WithValue(ctx, keyContext, rctx)
		ctx = xlog.ContextWithKV(ctx, "ctx", rctx.ID)
	}
	return ctx
}

// WithMetaFromContext ensures the outgoing gRPC metadata of ctx carries the
// correlation ID under CorrelationIDgRPCHeaderName, generating and storing
// a new ID in the context when none exists. Use it before making a gRPC
// client call.
func WithMetaFromContext(ctx context.Context) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok || len(md.Get(CorrelationIDgRPCHeaderName)) == 0 {
		v := ctx.Value(keyContext)
		if v == nil {
			rctx := &RequestContext{
				ID: certutil.RandomString(IDSize),
			}
			ctx = context.WithValue(ctx, keyContext, rctx)
			ctx = xlog.ContextWithKV(ctx, "ctx", rctx.ID)
			v = rctx
		}
		cid := v.(*RequestContext).ID
		return metadata.AppendToOutgoingContext(ctx, CorrelationIDgRPCHeaderName, cid)
	}
	return ctx
}

// WithMetaFromRequest returns context with Correlation ID
// for the outgoing gRPC call, on wire or in memory.
// Both Incoming and Outgoing metadata are created out of
// HTTP request headers with x- and grpc- prefixes.
func WithMetaFromRequest(req *http.Request) context.Context {
	cid := correlationID(req)
	rctx := &RequestContext{
		ID: cid,
	}
	ctx := context.WithValue(req.Context(), keyContext, rctx)
	ctx = xlog.ContextWithKV(ctx, "ctx", rctx.ID)
	md := metadata.MD{}
	md.Set(CorrelationIDgRPCHeaderName, cid)
	kv := []string{CorrelationIDgRPCHeaderName, cid}
	grpcCorrelationKey := strings.ToLower(CorrelationIDgRPCHeaderName)
	httpCorrelationKey := strings.ToLower(header.XCorrelationID)
	forwardRequestID := false
	for key, values := range req.Header {
		// Normalize the header key to lowercase for gRPC metadata
		grpcKey := strings.ToLower(key)
		if grpcKey == grpcCorrelationKey || grpcKey == httpCorrelationKey {
			continue
		}
		if grpcKey == requestIDgRPCHeaderName {
			forwardRequestID = true
			continue
		}
		isX := strings.HasPrefix(grpcKey, "x-")
		isGRPC := strings.HasPrefix(grpcKey, "grpc-")
		if isX || isGRPC || grpcKey == "authorization" || grpcKey == "date" || grpcKey == "timestamp" {
			for _, value := range values {
				// Add each value to the metadata
				kv = append(kv, grpcKey, value)
				md.Append(grpcKey, value)
			}
		}
	}
	if forwardRequestID {
		md.Set(requestIDgRPCHeaderName, cid)
		kv = append(kv, requestIDgRPCHeaderName, cid)
	}

	// create both Incoming and Outgoing metadata
	ctx = metadata.NewIncomingContext(ctx, md)
	return metadata.AppendToOutgoingContext(ctx, kv...)
}

// NewFromContext returns a fresh context.Background (detached from ctx's
// cancellation and deadline) that carries ctx's correlation ID, or a new
// one, both as a context value and as outgoing gRPC metadata. Use it for
// background work that should outlive the request.
func NewFromContext(ctx context.Context) context.Context {
	cid := ID(ctx)
	if cid == "" {
		cid = certutil.RandomString(IDSize)
	}
	rctx := &RequestContext{
		ID: cid,
	}
	ctx = context.WithValue(context.Background(), keyContext, rctx)
	ctx = xlog.ContextWithKV(ctx, "ctx", rctx.ID)
	return metadata.AppendToOutgoingContext(ctx, CorrelationIDgRPCHeaderName, cid)
}
