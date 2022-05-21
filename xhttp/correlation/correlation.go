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

// IDSize specifies a size in characters for the correlation ID
const IDSize = 12

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
				correlationID: correlationID(r),
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
				correlationID: correlationIDFromGRPC(ctx),
			}
			ctx = context.WithValue(ctx, keyContext, rctx)
		}

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
			xid := md["x-correlation-id"]
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
		logger.KV(xlog.TRACE, "ctx", corID, "incoming_ctx", incomingID)
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
			correlationID: certutil.RandomString(IDSize),
		}
		ctx = context.WithValue(ctx, keyContext, rctx)
	}
	return ctx
}

// WithMetaFromRequest returns context with Correlation ID
func WithMetaFromRequest(req *http.Request) context.Context {
	cid := correlationID(req)
	rctx := &RequestContext{
		correlationID: cid,
	}
	ctx := context.WithValue(req.Context(), keyContext, rctx)
	return metadata.AppendToOutgoingContext(ctx, "x-correlation-id", cid)
}

// NewFromContext returns new Background context with Correlation ID from incoming context
func NewFromContext(ctx context.Context) context.Context {
	cid := ID(ctx)
	if cid == "" {
		cid = certutil.RandomString(IDSize)
	}
	rctx := &RequestContext{
		correlationID: cid,
	}
	ctx = context.WithValue(context.Background(), keyContext, rctx)
	return metadata.AppendToOutgoingContext(ctx, "x-correlation-id", cid)
}
