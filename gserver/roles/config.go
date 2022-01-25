package roles

// IdentityMap contains configuration for the roles
type IdentityMap struct {
	// TLS identity map
	TLS TLSIdentityMap `json:"tls" yaml:"tls"`
	// JWT identity map
	JWT JWTIdentityMap `json:"jwt" yaml:"jwt"`
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
	// Enable TLS identities
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Audience specifies the token audience
	Audience string `json:"audience" yaml:"audience"`
	// Roles is a map of role to JWT identity
	Roles map[string][]string `json:"roles" yaml:"roles"`
}
