package correlation

import (
	"context"
	"net/http"
	"strings"

	"github.com/effective-security/porto/x/slices"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/xhttp", "correlation")

// CorrelationIDgRPCHeaderName specifies default name for gRPC header
var CorrelationIDgRPCHeaderName = "x-correlation-id"

type contextKey int

const (
	keyContext contextKey = iota
	keyCorrelation
)

// IDSize specifies a size in characters for the correlation ID
const IDSize = 12

// Correlator interface allows to provide request ID
type Correlator interface {
	CorrelationID() string
}

// RequestContext represents user contextual information about a request being processed by the server,
// it includes ID, aka Request-ID or Correlation-ID (for cross system request correlation).
type RequestContext struct {
	ID string
}

// NewHandler returns a handler that will extact/add the correlationID from the request
// and stash them away in the request context for later handlers to use.
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

// NewAuthUnaryInterceptor returns grpc.UnaryServerInterceptor that
// identity to the context
func NewAuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		var rctx *RequestContext
		v := ctx.Value(keyContext)
		if v == nil {
			rctx = &RequestContext{
				ID: correlationIDFromGRPC(ctx),
			}
			ctx = context.WithValue(ctx, keyContext, rctx)
		}

		// add correlationID to logs as "ctx"
		ctx = xlog.ContextWithKV(ctx, "ctx", rctx.ID)

		return handler(ctx, req)
	}
}

// correlationIDFromGRPC will find or create a requestID for this request.
func correlationIDFromGRPC(ctx context.Context) string {
	corID := ID(ctx)
	if corID == "" {
		incomingID := ""
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			xid := md[CorrelationIDgRPCHeaderName]
			if len(xid) == 0 {
				xid = md["x-request-id"]
			}
			if len(xid) == 0 {
				xid = md[header.XCorrelationID]
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

// Value returns correlation RequestContext from the context
func Value(ctx context.Context) *RequestContext {
	v := ctx.Value(keyContext)
	if r, ok := v.(*RequestContext); ok {
		return r
	}
	return nil
}

// ID returns correlation ID from the context
func ID(ctx context.Context) string {
	corID := ""
	v := Value(ctx)
	if v != nil {
		corID = v.ID
	}
	return corID
}

// WithID returns context with Correlation ID,
// if the context alread has Correlation ID,
// the original is returned
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

// WithMetaFromContext returns context with Correlation ID
// for the outgoing gRPC call
func WithMetaFromContext(ctx context.Context) context.Context {
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

// WithMetaFromRequest returns context with Correlation ID
// for the outgoing gRPC call
func WithMetaFromRequest(req *http.Request) context.Context {
	cid := correlationID(req)
	rctx := &RequestContext{
		ID: cid,
	}
	ctx := context.WithValue(req.Context(), keyContext, rctx)
	ctx = xlog.ContextWithKV(ctx, "ctx", rctx.ID)
	return metadata.AppendToOutgoingContext(ctx, CorrelationIDgRPCHeaderName, cid)
}

// NewFromContext returns new Background context with Correlation ID from incoming context
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
