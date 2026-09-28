// Package identity extracts the caller's identity (role, subject, tenant,
// claims, auth method) and connection details (client IP, user agent,
// target) from HTTP requests or gRPC contexts and exposes them through the
// request context.
//
// Servers install NewContextHandler (HTTP) or NewAuthUnaryInterceptor /
// NewStreamServerInterceptor (gRPC) with an identity mapper; handlers then
// read the result:
//
//	h := identity.NewContextHandler(next, myMapper) // ProviderFromRequest
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//		rc := identity.FromRequest(r)
//		role := rc.Identity().Role()
//		ip := rc.ClientIP()
//	}
//
// When no identity is present a guest identity (role "guest") is returned,
// never nil. GuestIdentityMapper / GuestIdentityForContext are the default
// mappers. By default client IPs come from the socket peer. A server may
// opt in to forwarding headers with ParseTrustedProxies and
// NewTrustedProxyHandler (HTTP) or WithTrustedProxies (gRPC context). The
// configured proxies must overwrite incoming forwarding headers.
// NewTrustedProxyHandler resolves the client IP once per request and
// ClientIPFromRequest returns that value in later handlers:
//
//	trust, err := identity.ParseTrustedProxies([]string{"10.2.0.0/16"})
//	if err != nil {
//		return err
//	}
//	h := identity.NewTrustedProxyHandler(identity.NewContextHandler(next, myMapper), trust)
//
// A request without a socket peer, such as one built with http.NewRequest
// and served in process, has no client IP: ClientIPFromRequest returns "".
package identity
