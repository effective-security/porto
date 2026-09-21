package identity

import (
	"context"
	"net/http"

	"cmp"

	"github.com/effective-security/x/netutil"
	"github.com/effective-security/xpki/jwt"
)

// GuestRoleName is default role name for guest
const GuestRoleName = "guest"

// AuthMethod identifies how the caller was authenticated.
type AuthMethod int

// Authentication methods reported by Identity.AuthMethod.
const (
	// MethodNone means the caller was not authenticated (guest).
	MethodNone AuthMethod = iota
	// MethodCertificate means a TLS client certificate was used.
	MethodCertificate
	// MethodAWS means AWS request signing was used.
	MethodAWS
	// MethodDPoP means a DPoP-bound access token was used.
	MethodDPoP
	// MethodJWT means a bearer JWT was used.
	MethodJWT
	// MethodJWTCookie means a JWT carried in a cookie was used.
	MethodJWTCookie
)

// String returns the method name ("Certificate", "AWS", "DPoP", "JWT",
// "JWTCookie"), or "None" for MethodNone and unknown values.
func (m AuthMethod) String() string {
	switch m {
	case MethodCertificate:
		return "Certificate"
	case MethodAWS:
		return "AWS"
	case MethodDPoP:
		return "DPoP"
	case MethodJWT:
		return "JWT"
	case MethodJWTCookie:
		return "JWTCookie"
	default:
		return "None"
	}
}

// Identity contains information about the identity of an API caller.
// Implementations are immutable values; create them with NewIdentity.
type Identity interface {
	// String returns the identity as a single string value
	// in the format of {tenant/}subject{:role}
	String() string
	// Role returns the role used for authorization (see restserver/authz).
	Role() string
	// Subject returns the caller's subject: a certificate CommonName, a JWT
	// "email" claim, or similar.
	Subject() string
	// Tenant returns the tenant the identity belongs to, or "".
	Tenant() string
	// Claims returns a copy of the application-specific claims.
	Claims() jwt.MapClaims
	// AccessToken returns the raw access token presented, or "".
	AccessToken() string
	// TokenType returns the token type (e.g. "Bearer", "DPoP"), or "".
	TokenType() string
	// AuthMethod returns how the caller was authenticated.
	AuthMethod() AuthMethod
}

// ProviderFromRequest maps an HTTP request to the caller's Identity. It is
// used by NewContextHandler; returning an error rejects the request with
// 401, returning a nil Identity yields the guest identity.
type ProviderFromRequest func(*http.Request) (Identity, error)

// ProviderFromContext maps a gRPC request context and full method name to
// the caller's Identity. It is used by the gRPC interceptors; returning an
// error rejects the call with codes.PermissionDenied, returning a nil
// Identity yields the guest identity.
type ProviderFromContext func(ctx context.Context, uri string) (Identity, error)

// NewIdentity returns an immutable Identity with the given attributes.
// claims may be nil; when provided they are copied.
func NewIdentity(role, subject, tenant string, claims map[string]any, accessToken, tokenType string, authMethod AuthMethod) Identity {
	id := identity{
		role:        role,
		subject:     subject,
		tenant:      tenant,
		claims:      jwt.MapClaims{},
		accessToken: accessToken,
		tokenType:   tokenType,
		authMethod:  authMethod,
	}
	if claims != nil {
		_ = id.claims.Add(claims)
	}
	return id
}

type identity struct {
	// subject of identity
	// It can be CommonName extracted from certificate,
	// or "email" claim in JWT
	subject string
	// tenant of identity, if supported
	tenant string
	// role of identity
	role string
	// extra user info, specific to the application
	claims jwt.MapClaims

	accessToken string
	tokenType   string
	authMethod  AuthMethod
}

// Subject returns the client's subject.
// It can be CommonName extracted from certificate,
// or "email" claim in JWT
func (c identity) Subject() string {
	return c.subject
}

// Tenant returns the tenant that identity belongs to, or "".
func (c identity) Tenant() string {
	return c.tenant
}

// Role returns the clients role
func (c identity) Role() string {
	return c.role
}

// AccessToken returns AccessToken for identity
func (c identity) AccessToken() string {
	return c.accessToken
}

// TokenType returns the token type for the identity
func (c identity) TokenType() string {
	return c.tokenType
}

// AuthMethod returns auth type for Identity
func (c identity) AuthMethod() AuthMethod {
	return c.authMethod
}

// Claims returns application specific user info
func (c identity) Claims() jwt.MapClaims {
	res := jwt.MapClaims{}
	_ = res.Add(c.claims)
	return res
}

// String returns the identity as a single string value
// in the format of {tenant/}subject{:role}
func (c identity) String() string {
	s := cmp.Or(c.subject, "unknown")
	if c.tenant != "" {
		s = c.tenant + "/" + s
	}
	if c.role != "" && c.role != c.subject {
		s = s + ":" + c.role
	}

	return s
}

// GuestIdentityMapper is a ProviderFromRequest that always returns the
// guest role, with the subject set to the TLS client certificate CommonName
// when one was presented, or "unknown". It is restserver's default mapper.
func GuestIdentityMapper(r *http.Request) (Identity, error) {
	var name string
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		name = "unknown"
	} else {
		name = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return NewIdentity(GuestRoleName, name, "", nil, "", "", MethodNone), nil
}

// GuestIdentityForContext is a ProviderFromContext that always returns the
// guest role with an empty subject.
func GuestIdentityForContext(_ context.Context, _ string) (Identity, error) {
	return NewIdentity(GuestRoleName, "", "", nil, "", "", MethodNone), nil
}

// WithTestIdentity returns a copy of r whose context carries the given
// identity (with the local IP as client IP), for use in unit tests.
func WithTestIdentity(r *http.Request, identity Identity) *http.Request {
	ipaddr, _ := netutil.GetLocalIP()
	ctx := &RequestContext{
		identity: identity,
		clientIP: ipaddr,
	}
	c := context.WithValue(r.Context(), keyContext, ctx)
	return r.WithContext(c)
}
