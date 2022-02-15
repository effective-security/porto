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

type contextKey int

const (
	keyContext contextKey = iota
	keyCorrelation
)

// RequestContext represents user contextual information about a request being processed by the server,
// it includes CorrelationID [for cross system request correlation].
type RequestContext struct {
	correlationID string
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
				correlationID: extractCorrelationID(r),
			}
			r = r.WithContext(context.WithValue(ctx, keyContext, rctx))
		} else {
			rctx = v.(*RequestContext)
		}

		w.Header().Set(header.XCorrelationID, rctx.correlationID)
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
				correlationID: extractCorrelationIDFromGRPC(ctx),
			}
			ctx = context.WithValue(ctx, keyContext, rctx)
		}

		return handler(ctx, req)
	}
}

// extractCorrelationIDFromGRPC will find or create a requestID for this request.
func extractCorrelationIDFromGRPC(ctx context.Context) string {
	corID := certutil.RandomString(8)
	incomingID := ""
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		xid := md["x-correlation-id"]
		if len(xid) == 0 {
			xid = md[header.XCorrelationID]
		}
		if len(xid) > 0 {
			incomingID = xid[0]
		}
	}
	if incomingID != "" {
		corID += "_" + slices.StringUpto(incomingID, 8)
	}
	logger.KV(xlog.TRACE, "ctx", corID, "incoming_ctx", incomingID)

	return corID
}

// extractCorrelationID will find or create a requestID for this http request.
func extractCorrelationID(req *http.Request) string {
	// 8 chars will have enough entropy
	// to correlate requests,
	// without the large footprint in the logs
	corID := ""
	incomingID := req.Header.Get(header.XCorrelationID)
	if incomingID == "" {
		incomingID = req.Header.Get("X-Request-ID")
	}

	if incomingID != "" {
		corID = slices.StringUpto(incomingID, 8)
	} else {
		corID = certutil.RandomString(8)
	}

	l := xlog.DEBUG
	if strings.Contains(req.Header.Get(header.Accept), "json") {
		l = xlog.TRACE
	}
	logger.KV(l, "ctx", corID, "incoming_ctx", incomingID, "path", req.URL.Path)

	return corID
}

// ID returns correlation ID from the context
func ID(ctx context.Context) string {
	corID := ""
	v := ctx.Value(keyContext)
	if v != nil {
		rctx := v.(*RequestContext)
		corID = rctx.correlationID
	}
	return corID
}

// WithID returns context with Correlation ID
func WithID(ctx context.Context) context.Context {
	v := ctx.Value(keyContext)
	if v == nil {
		rctx := &RequestContext{
			correlationID: certutil.RandomString(8),
		}
		ctx = context.WithValue(ctx, keyContext, rctx)
	}
	return ctx
}

// WithMetaFromRequest returns context with Correlation ID
func WithMetaFromRequest(req *http.Request) context.Context {
	cid := extractCorrelationID(req)
	rctx := &RequestContext{
		correlationID: cid,
	}
	ctx := context.WithValue(req.Context(), keyContext, rctx)
	return metadata.AppendToOutgoingContext(ctx, "x-correlation-id", cid)
}
