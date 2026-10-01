// Package roles maps authenticated callers to porto roles for both HTTP and
// gRPC requests.
//
// New builds an IdentityProvider from an IdentityMap. The provider inspects the
// Authorization header (or gRPC "authorization" metadata) and, depending on
// the token type, verifies an AWS STS presigned GetCallerIdentity URL ("AWS4"),
// a DPoP-bound JWT ("DPoP") or a bearer JWT ("Bearer"); it can also fall back
// to a JWT stored in a cookie (with CSRF double-submit checks for unsafe HTTP
// methods and every gRPC call) and to a client TLS certificate carrying a
// SPIFFE URI SAN. The resulting identity.Identity carries the mapped role,
// subject, tenant and claims; unauthenticated requests receive the guest
// identity.
//
// For gRPC, DPoP proofs sign POST with an absolute htu of
// https://<incoming :authority><full method path>. Relative-path proofs
// fail authentication. A proxy must preserve that authority and method path.
//
// The provider is wired into gserver via Config.IdentityMap, but can be used
// directly with xhttp/identity:
//
//	prov, err := roles.New(&roles.IdentityMap{
//		JWT: roles.JWTIdentityMap{
//			Enabled:                  true,
//			Issuer:                   "https://issuer.example.com",
//			Audience:                 "api",
//			DefaultAuthenticatedRole: roles.JWTUserRoleName,
//			Roles: map[string][]string{"admin": {"alice@example.com"}},
//		},
//	}, jwtParser)
//	if err != nil {
//		return err
//	}
//	h := identity.NewContextHandler(next, prov.IdentityFromRequest)
//
// YAML layout of IdentityMap:
//
//	identity_map:
//	  strict: false
//	  skip_auth: ["/healthz"]
//	  cookies: {auth: "auth_token", csrf: "csrf_token"}
//	  tls: {enabled: true, default_authenticated_role: tls_user, roles: {admin: ["spiffe://trust/ns/app"]}}
//	  jwt: {enabled: true, issuer: "...", audience: "...", roles: {admin: ["alice@example.com"]}}
//	  jwt_dpop: {enabled: false}
//	  aws: {enabled: true, allowed_accounts: ["123456789012"], roles: {deployer: ["123456789012:assumed-role/ci"]}}
package roles
