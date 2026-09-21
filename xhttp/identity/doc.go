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
// mappers. ClientIPFromRequest trusts X-Forwarded-For and X-Real-Ip headers,
// so it should only be relied on behind a proxy that sets them.
package identity
