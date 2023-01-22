// Package identity extracts the callers contextual identity information from the HTTP/TLS
// requests and exposes them for access via the generalized go context model.
package identity

import (
	"context"
	"net/http"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/xhttp", "context")

type contextKey int

const (
	keyContext contextKey = iota
	keyIdentity
)

// RequestContext represents user contextual information about a request being processed by the server,
// it includes identity, CorrelationID [for cross system request correlation].
type RequestContext struct {
	identity Identity
	clientIP string
}

// NewRequestContext creates a request context with a specific identity.
func NewRequestContext(id Identity) *RequestContext {
	return &RequestContext{
		identity: id,
	}
}

// Context represents user contextual information about a request being processed by the server,
// it includes identity, CorrelationID [for cross system request correlation].
type Context interface {
	Identity() Identity
	ClientIP() string
}

// FromContext extracts the RequestContext stored inside a go context. Returns null if no such value exists.
func FromContext(ctx context.Context) *RequestContext {
	ret, _ := ctx.Value(keyContext).(*RequestContext)
	if ret == nil {
		ret = &RequestContext{
			identity: guestIdentity,
		}
	}
	return ret
}

// AddToContext returns a new golang context that adds `rq` as the request context.
func AddToContext(ctx context.Context, rq *RequestContext) context.Context {
	return context.WithValue(ctx, keyContext, rq)
}

// FromRequest returns the full context ascocicated with this http request.
func FromRequest(r *http.Request) *RequestContext {
	return FromContext(r.Context())
}

// NewContextHandler returns a handler that will extact the role & contextID from the request
// and stash them away in the request context for later handlers to use.
// Also adds header to indicate which host is currently servicing the request
func NewContextHandler(delegate http.Handler, identityMapper ProviderFromRequest) http.Handler {
	h := func(w http.ResponseWriter, r *http.Request) {
		var rctx *RequestContext
		v := r.Context().Value(keyContext)
		if v == nil {
			clientIP := ClientIPFromRequest(r)
			idn, err := identityMapper(r)
			if err != nil {
				logger.ContextKV(r.Context(), xlog.WARNING,
					"reason", "identityMapper",
					"ip", clientIP,
					"err", err.Error())
				marshal.WriteJSON(w, r, httperror.Unauthorized("request denied for this identity"))
				return
			}

			rctx = &RequestContext{
				identity: idn,
				clientIP: clientIP,
			}

			var email string
			if claims := idn.Claims(); len(claims) > 0 {
				email = claims.String("email")
			}
			ctx := r.Context()
			role := idn.Role()
			if role != "guest" {
				ctx = xlog.ContextWithKV(ctx,
					"tenant", idn.Tenant(),
					"user", idn.Subject(),
					"email", email,
					"role", role)
			}
			r = r.WithContext(context.WithValue(ctx, keyContext, rctx))
		}

		delegate.ServeHTTP(w, r)
	}
	return http.HandlerFunc(h)
}

var guestIdentity = NewIdentity(GuestRoleName, "", "", nil, "", "")

// NewAuthUnaryInterceptor returns grpc.UnaryServerInterceptor that
// identity to the context
func NewAuthUnaryInterceptor(identityMapper ProviderFromContext) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		var id Identity
		var err error
		id, err = identityMapper(ctx, info.FullMethod)
		if err != nil {
			logger.ContextKV(ctx, xlog.DEBUG,
				"reason", "access_denied",
				"method", info.FullMethod,
				"err", err.Error())
			return nil, status.Errorf(codes.PermissionDenied, "unable to get identity: %v", err.Error())
		}
		if id == nil {
			id = guestIdentity
		}
		ctx = AddToContext(ctx, NewRequestContext(id))
		role := id.Role()
		if role != "guest" {
			ctx = xlog.ContextWithKV(ctx, "user", id.Subject(), "role", role)
		}

		return handler(ctx, req)
	}
}

// Identity returns request's identity
func (c *RequestContext) Identity() Identity {
	return c.identity
}

// ClientIP returns request's IP
func (c *RequestContext) ClientIP() string {
	return c.clientIP
}
