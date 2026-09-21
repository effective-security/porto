package roles

// IdentityMap configures the authentication methods and role mappings used
// by the IdentityProvider returned by New. Every method is disabled by default.
type IdentityMap struct {
	// DebugLogs enables extra debug logs of incoming gRPC metadata.
	DebugLogs bool `json:"debug_logs" yaml:"debug_logs"`
	// Strict returns an error when an applicable auth method fails; without
	// it the remaining methods are tried and the request falls back to guest.
	// Cookie-based JWT failures never return an error.
	Strict bool `json:"strict" yaml:"strict"`

	// Cookies configuration
	Cookies CookiesConfig `json:"cookies" yaml:"cookies"`
	// SkipAuthPaths lists exact HTTP paths for which authentication is skipped
	// and the guest identity is returned (HTTP only; not applied to gRPC).
	SkipAuthPaths []string `json:"skip_auth" yaml:"skip_auth"`
	// TLS maps client certificate SPIFFE URIs to roles.
	TLS GenericIdentityMap `json:"tls" yaml:"tls"`
	// JWT maps bearer JWT claims to roles.
	JWT JWTIdentityMap `json:"jwt" yaml:"jwt"`
	// DPoP maps DPoP-bound JWT claims to roles.
	DPoP JWTIdentityMap `json:"jwt_dpop" yaml:"jwt_dpop"`
	// AWS maps AWS STS caller identities to roles.
	AWS AWSIdentityMap `json:"aws" yaml:"aws"`
}

// GetCookiesConfig returns the cookie configuration; safe on a nil receiver.
func (i *IdentityMap) GetCookiesConfig() CookiesConfig {
	if i == nil {
		return CookiesConfig{}
	}
	return i.Cookies
}

// CookiesConfig configures cookie-based JWT authentication, used when no
// Authorization header is present and JWT is enabled.
type CookiesConfig struct {
	// Auth specifies the name of the cookie to be used for JWT authentication.
	// If empty, the auth cookie is not used.
	Auth string `json:"auth" yaml:"auth"`
	// CSRF specifies the name of the cookie to be used for CSRF protection
	// (double-submit with the X-CSRF-Token header on unsafe methods).
	// If empty, cookie authentication over HTTP is disabled.
	CSRF string `json:"csrf" yaml:"csrf"`
	// Domain specifies the domain of the cookie to be used for authentication and CSRF protection.
	// If empty, the cookie domain is not set.
	Domain string `json:"domain" yaml:"domain"`
}

// GenericIdentityMap maps TLS client certificate identities to roles.
type GenericIdentityMap struct {
	// DefaultAuthenticatedRole specifies role name for identity, if not found in maps
	DefaultAuthenticatedRole string `json:"default_authenticated_role" yaml:"default_authenticated_role"`
	// Enabled enables TLS client certificate identities
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Roles maps a role name to the list of SPIFFE URIs (e.g. "spiffe://trust/ns/svc")
	Roles map[string][]string `json:"roles" yaml:"roles"`
}

// AWSIdentityMap maps AWS STS caller identities ("AWS4" presigned
// GetCallerIdentity URL tokens) to roles.
type AWSIdentityMap struct {
	// DefaultAuthenticatedRole specifies role name for identity, if not found in maps
	DefaultAuthenticatedRole string `json:"default_authenticated_role" yaml:"default_authenticated_role"`
	// Enabled enables AWS identities
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Roles maps a role name to a list of caller identities, either the full
	// ARN or the subject form "<account>:<resource-type>/<name>"
	// (e.g. "123456789012:assumed-role/ci").
	Roles map[string][]string `json:"roles" yaml:"roles"`
	// AllowedAccounts is a list of allowed AWS accounts,
	// if empty, all accounts are allowed
	AllowedAccounts []string `json:"allowed_accounts" yaml:"allowed_accounts"`
}

// JWTIdentityMap maps JWT claims to roles; it is used for both bearer JWT
// and DPoP-bound JWT authentication.
type JWTIdentityMap struct {
	// DefaultAuthenticatedRole specifies role name for identity, if not found in maps
	DefaultAuthenticatedRole string `json:"default_authenticated_role" yaml:"default_authenticated_role"`
	// Enabled enables JWT identities; requires a jwt.Parser to be passed to New
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Issuer specifies the expected token issuer; empty disables the check
	Issuer string `json:"issuer" yaml:"issuer"`
	// Audience specifies the expected token audience; empty disables the check
	Audience string `json:"audience" yaml:"audience"`
	// SubjectClaim specifies claim name to be used as Subject,
	// by default it's `sub`, but can be changed to `email` etc
	SubjectClaim string `json:"subject_claim" yaml:"subject_claim"`
	// RoleClaim specifies claim name to be used for role mapping,
	// by default it's `email`, but can be changed to `sub` etc
	RoleClaim string `json:"role_claim" yaml:"role_claim"`
	// TenantClaim specifies claim name to be used for tenant mapping,
	// by default it's `tenant`, but can be changed to `org` etc
	TenantClaim string `json:"tenant_claim" yaml:"tenant_claim"`
	// Roles maps a role name to a list of RoleClaim values (by default emails)
	Roles map[string][]string `json:"roles" yaml:"roles"`
}
