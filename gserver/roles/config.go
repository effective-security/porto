package roles

// IdentityMap contains configuration for the roles
type IdentityMap struct {
	// TLS identity map
	TLS TLSIdentityMap `json:"tls" yaml:"tls"`
	// JWT identity map
	JWT JWTIdentityMap `json:"jwt" yaml:"jwt"`
	// DPoP identity map
	DPoP JWTIdentityMap `json:"jwt_dpop" yaml:"jwt_dpop"`
}

// TLSIdentityMap provides roles for TLS
type TLSIdentityMap struct {
	// DefaultAuthenticatedRole specifies role name for identity, if not found in maps
	DefaultAuthenticatedRole string `json:"default_authenticated_role" yaml:"default_authenticated_role"`
	// Enable TLS identities
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Roles is a map of role to TLS identity
	Roles map[string][]string `json:"roles" yaml:"roles"`
}

// JWTIdentityMap provides roles for JWT
type JWTIdentityMap struct {
	// DefaultAuthenticatedRole specifies role name for identity, if not found in maps
	DefaultAuthenticatedRole string `json:"default_authenticated_role" yaml:"default_authenticated_role"`
	// Enable JWT identities
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Issuer specifies the token issuer to check for
	Issuer string `json:"issuer" yaml:"issuer"`
	// Audience specifies the token audience to check for
	Audience string `json:"audience" yaml:"audience"`
	// SubjectClaim specifies claim name to be used as Subject,
	// by default it's `sub`, but can be changed to `email` etc
	SubjectClaim string `json:"subject_claim" yaml:"subject_claim"`
	// Roles is a map of role to JWT identity
	Roles map[string][]string `json:"roles" yaml:"roles"`
}
