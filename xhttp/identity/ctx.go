package identity

import (
	"context"
	"errors"
	"net/http"
	"runtime/debug"

	"github.com/effective-security/porto/pkg/streamctx"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/xhttp", "context")

// msgInvalidIdentity is the client-facing message for identity mapper
// failures; the mapper's error text is only logged.
const msgInvalidIdentity = "invalid identity"

type contextKey int

const (
	keyContext contextKey = iota
	keyIdentity
)

// RequestContext is the per-request value stored in the context by
// NewContextHandler and the gRPC interceptors: the caller's Identity, client
// IP, target (HTTP path or gRPC method) and user agent. It implements
// Context. Correlation IDs live in xhttp/correlation, not here.
type RequestContext struct {
	identity Identity
	clientIP string
	// target of the request, e.g. HTTP path or gRPC method
	target    string
	userAgent string
}

// NewRequestContext creates a request context with a specific identity and
// target; client IP and user agent are left empty. Store it with AddToContext.
func NewRequestContext(id Identity, target string) *RequestContext {
	return &RequestContext{
		identity: id,
		target:   target,
	}
}

// Context is the read-only view of RequestContext.
type Context interface {
	// Identity returns the caller's identity; never nil (guest when unknown).
	Identity() Identity
	// ClientIP returns the client IP as determined by ClientIPFromRequest or
	// ClientIPFromGRPC, or "".
	ClientIP() string
	// Target of the request, e.g. HTTP path or gRPC method
	Target() string
	// UserAgent returns the User-Agent header (or user-agent / x-user-agent
	// gRPC metadata), or "".
	UserAgent() string
}

// FromContext returns the RequestContext stored in ctx. When none exists it
// returns a new RequestContext with the guest identity, never nil.
func FromContext(ctx context.Context) *RequestContext {
	ret, _ := ctx.Value(keyContext).(*RequestContext)
	if ret == nil {
		ret = &RequestContext{
			identity: guestIdentity,
		}
	}
	return ret
}

// AddToContext returns a child context carrying rq as the request context,
// as later returned by FromContext.
func AddToContext(ctx context.Context, rq *RequestContext) context.Context {
	return context.WithValue(ctx, keyContext, rq)
}

// FromRequest returns the RequestContext for r (guest when none was stored),
// filling in target, client IP and user agent from the request when they are
// empty. Note that it updates the stored RequestContext in place.
func FromRequest(r *http.Request) *RequestContext {
	c := FromContext(r.Context())
	if c.target == "" {
		c.target = r.URL.Path
	}
	if c.clientIP == "" {
		c.clientIP = ClientIPFromRequest(r)
	}
	if c.userAgent == "" {
		c.userAgent = r.Header.Get(header.UserAgent)
	}
	return c
}

// NewContextHandler returns middleware that calls identityMapper for each
// request and stores the resulting RequestContext (identity, client IP,
// path, user agent) in the request context for later handlers. A mapper
// error is logged and answered with a JSON 401 unauthorized response whose
// message is the generic "invalid identity", unless the error is (or wraps)
// an *httperror.Error with an HTTP status, which is written as is; the
// request is not forwarded. For non-guest identities tenant/user/email/role are also
// added to the xlog context fields. A RequestContext already present in the
// context (for example from WithTestIdentity) is left untouched.
func NewContextHandler(delegate http.Handler, identityMapper ProviderFromRequest) http.Handler {
	h := func(w http.ResponseWriter, r *http.Request) {
		var rctx *RequestContext
		v := r.Context().Value(keyContext)
		if v == nil {
			target := r.URL.Path
			clientIP := ClientIPFromRequest(r)
			idn, err := identityMapper(r)
			if err != nil {
				logger.ContextKV(r.Context(), xlog.WARNING,
					"reason", "identityMapper",
					"ip", clientIP,
					"target", target,
					"err", err.Error())

				marshal.WriteJSON(w, r, identityError(r.Context(), err))
				return
			}
			if idn == nil {
				idn = guestIdentity
			}

			rctx = &RequestContext{
				identity:  idn,
				clientIP:  clientIP,
				target:    target,
				userAgent: r.Header.Get(header.UserAgent),
			}

			var email string
			if claims := idn.Claims(); len(claims) > 0 {
				email = claims.String("email")
			}
			ctx := r.Context()
			role := idn.Role()
			if role != GuestRoleName {
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

var guestIdentity = NewIdentity(GuestRoleName, "", "", nil, "", "", MethodNone)

// identityError converts an identity mapper failure into the error returned
// to the caller. A non-nil *httperror.Error found in err's chain is the
// mapper's deliberate, client-safe answer and is returned as is (and not
// modified, so mappers may share such values), provided it carries a valid
// HTTP status; any other error, including a typed nil, keeps its text in the
// log and the caller gets a new generic 401 unauthorized
// (codes.Unauthenticated) carrying the correlation ID of ctx and err as its
// cause.
func identityError(ctx context.Context, err error) *httperror.Error {
	if he, ok := errors.AsType[*httperror.Error](err); ok && he != nil && he.HTTPStatus >= http.StatusContinue {
		return he
	}
	return httperror.Unauthorized(msgInvalidIdentity).WithContext(ctx).WithCause(err)
}

func getMdHeader(md metadata.MD, name string) string {
	vals := md.Get(name)
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func createIdentityContext(ctx context.Context, methodFullMethod string, identityMapper ProviderFromContext) (context.Context, error) {
	var id Identity
	var err error
	id, err = identityMapper(ctx, methodFullMethod)
	if err != nil {
		logger.ContextKV(ctx, xlog.WARNING,
			"reason", "access_denied",
			"method", methodFullMethod,
			"err", err.Error())
		he := identityError(ctx, err)
		if he.RPCStatus == codes.OK {
			// A code without a gRPC mapping would read as success on the
			// wire; report the failure with the generic authentication code.
			return nil, status.Error(codes.Unauthenticated, he.Message)
		}
		return nil, he
	}
	if id == nil {
		id = guestIdentity
	}
	rc := NewRequestContext(id, methodFullMethod)

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		rc.userAgent = getMdHeader(md, "user-agent")
		if rc.userAgent == "" {
			rc.userAgent = getMdHeader(md, "x-user-agent")
		}
	}
	rc.clientIP = ClientIPFromGRPC(ctx)

	ctx = AddToContext(ctx, rc)
	role := id.Role()
	if role != GuestRoleName {
		tenant := id.Tenant()
		subject := id.Subject()
		entries := []any{"role", role}
		if tenant != "" {
			entries = append(entries, "tenant", tenant)
		}
		if subject != "" {
			entries = append(entries, "user", subject)
		}

		claims := id.Claims()
		if len(claims) > 0 {
			claims := id.Claims()
			email := claims.String("email")
			if email != "" {
				entries = append(entries, "email", email)
			}
			spiffe := claims.String("spiffe")
			if spiffe != "" {
				entries = append(entries, "spiffe", spiffe)
			}
		}
		ctx = xlog.ContextWithKV(ctx, entries...)
	}
	return ctx, nil
}

// NewAuthUnaryInterceptor returns a grpc.UnaryServerInterceptor that calls
// identityMapper with the full method name and stores the RequestContext
// (identity, client IP from a trusted proxy or the peer
// address, user agent) in the context. A mapper error is logged and fails
// the call with codes.Unauthenticated and the generic "invalid identity"
// message, unless it is (or wraps) an *httperror.Error with an HTTP status
// and a gRPC mapping, which is returned as is. Panics in the handler are recovered, logged and
// returned as an "unhandled exception" error. The optional trusted policy
// (only the first value is used) is stored with WithTrustedProxies; a nil or
// omitted policy keeps any policy already in the context.
func NewAuthUnaryInterceptor(identityMapper ProviderFromContext, trusted ...*TrustedProxies) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, si *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (res any, err error) {
		if len(trusted) > 0 && trusted[0] != nil {
			ctx = WithTrustedProxies(ctx, trusted[0])
		}
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
		ctx, err = createIdentityContext(ctx, si.FullMethod, identityMapper)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// NewStreamServerInterceptor returns the streaming counterpart of
// NewAuthUnaryInterceptor; the stream is wrapped with streamctx.WithContext
// so the handler sees the enriched context. It does not recover panics.
func NewStreamServerInterceptor(identityMapper ProviderFromContext, trusted ...*TrustedProxies) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		if len(trusted) > 0 && trusted[0] != nil {
			ctx = WithTrustedProxies(ctx, trusted[0])
		}
		ctx, err := createIdentityContext(ctx, info.FullMethod, identityMapper)
		if err != nil {
			return err
		}

		// Wrap with Context
		ss = streamctx.WithContext(ctx, ss)

		return handler(srv, ss)
	}
}

// Identity returns the request's identity; never nil.
func (c *RequestContext) Identity() Identity {
	return c.identity
}

// ClientIP returns the request's client IP, or "" when unknown.
func (c *RequestContext) ClientIP() string {
	return c.clientIP
}

// Target returns the request's target: the HTTP path or gRPC full method.
func (c *RequestContext) Target() string {
	return c.target
}

// UserAgent returns the request's user agent, or "".
func (c *RequestContext) UserAgent() string {
	return c.userAgent
}
