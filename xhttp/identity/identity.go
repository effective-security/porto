package identity

import (
	"context"
	"net/http"

	"github.com/effective-security/porto/x/netutil"
	"github.com/effective-security/xpki/jwt"
)

// GuestRoleName is default role name for guest
const GuestRoleName = "guest"

// Identity contains information about the identity of an API caller
type Identity interface {
	// String returns the identity as a single string value
	// in the format of role/subject
	String() string
	Role() string
	Subject() string
	Claims() map[string]interface{}
}

// ProviderFromRequest returns Identity from supplied HTTP request
type ProviderFromRequest func(*http.Request) (Identity, error)

// ProviderFromContext returns Identity from supplied context
type ProviderFromContext func(ctx context.Context) (Identity, error)

// NewIdentity returns a new Identity instance with the indicated role
func NewIdentity(role, subject string, claims map[string]interface{}) Identity {
	id := identity{
		role:    role,
		subject: subject,
		claims:  jwt.MapClaims{},
	}
	if claims != nil {
		id.claims.Add(claims)
	}
	return id
}

type identity struct {
	// subject of identity
	// It can be CommonName extracted from certificate,
	// or "email" claim in JWT
	subject string
	// role of identity
	role string
	// extra user info, specific to the application
	claims jwt.MapClaims
}

// Subject returns the client's subject.
// It can be CommonName extracted from certificate,
// or "email" claim in JWT
func (c identity) Subject() string {
	return c.subject
}

// Role returns the clients role
func (c identity) Role() string {
	return c.role
}

// Claims returns application specific user info
func (c identity) Claims() map[string]interface{} {
	res := jwt.MapClaims{}
	res.Add(c.claims)
	return res
}

// String returns the identity as a single string value
// in the format of role/subject
func (c identity) String() string {
	if c.role != c.subject && c.subject != "" {
		return c.role + "/" + c.subject
	}
	return c.role
}

// GuestIdentityMapper always returns "guest" for the role
func GuestIdentityMapper(r *http.Request) (Identity, error) {
	var name string
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		name = "ip:" + ClientIPFromRequest(r)
	} else {
		name = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return NewIdentity(GuestRoleName, name, nil), nil
}

// GuestIdentityForContext always returns "guest" for the role
func GuestIdentityForContext(ctx context.Context) (Identity, error) {
	return NewIdentity(GuestRoleName, "", nil), nil
}

// WithTestIdentity is used in unit tests to set HTTP request identity
func WithTestIdentity(r *http.Request, identity Identity) *http.Request {
	ipaddr, _ := netutil.GetLocalIP()
	ctx := &RequestContext{
		identity: identity,
		clientIP: ipaddr,
	}
	c := context.WithValue(r.Context(), keyContext, ctx)
	return r.WithContext(c)
}
