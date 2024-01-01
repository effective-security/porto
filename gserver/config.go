package gserver

import (
	"fmt"
	"net/url"
	"time"

	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/x/netutil"
)

// Config contains the configuration of the server
type Config struct {
	// DebugLogs allows to add extra debog logs
	DebugLogs bool `json:"debug_logs" yaml:"debug_logs"`

	// Description provides description of the server
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Disabled specifies if the service is disabled
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`

	// ClientURL is the public URL exposed to clients
	ClientURL string `json:"client_url" yaml:"client_url"`

	// ListenURLs is the list of URLs that the server will be listen on
	ListenURLs []string `json:"listen_urls" yaml:"listen_urls"`

	// ServerTLS provides TLS config for server
	ServerTLS *TLSInfo `json:"server_tls,omitempty" yaml:"server_tls,omitempty"`

	// SkipLogPaths if set, specifies a list of paths to not log.
	// this can be used for /v1/status/node or /metrics
	SkipLogPaths telemetry.LoggerSkipPaths `json:"logger_skip_paths,omitempty" yaml:"logger_skip_paths,omitempty"`

	// Services is a list of services to enable for this server
	Services []string `json:"services" yaml:"services"`

	// IdentityMap contains configuration for the roles
	IdentityMap *roles.IdentityMap `json:"identity_map" yaml:"identity_map"`

	// Authz contains configuration for the authorization module
	Authz *authz.Config `json:"authz" yaml:"authz"`

	// CORS contains configuration for CORS.
	CORS *CORS `json:"cors,omitempty" yaml:"cors,omitempty"`

	// RateLimit contains configuration for the rate limiter
	RateLimit *RateLimit `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`

	// Timeout settings
	Timeout struct {
		// Request is the timeout for client requests to finish.
		Request time.Duration `json:"request,omitempty" yaml:"request,omitempty"`
	} `json:"timeout" yaml:"timeout"`

	// KeepAlive settings
	KeepAlive KeepAliveCfg `json:"keep_alive" yaml:"keep_alive"`
}

// KeepAliveCfg settings
type KeepAliveCfg struct {
	// MinTime is the minimum interval that a client should wait before pinging server.
	MinTime time.Duration `json:"min_time,omitempty" yaml:"min_time,omitempty"`

	// Interval is the frequency of server-to-client ping to check if a connection is alive.
	Interval time.Duration `json:"interval,omitempty" yaml:"interval,omitempty"`

	// Timeout is the additional duration of wait before closing a non-responsive connection, use 0 to disable.
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// TLSInfo contains configuration info for the TLS
type TLSInfo struct {

	// CertFile specifies location of the cert
	CertFile string `json:"cert,omitempty" yaml:"cert,omitempty"`

	// KeyFile specifies location of the key
	KeyFile string `json:"key,omitempty" yaml:"key,omitempty"`

	// TrustedCAFile specifies location of the trusted Root file
	TrustedCAFile string `json:"trusted_ca,omitempty" yaml:"trusted_ca,omitempty"`

	// CRLFile specifies location of the CRL
	CRLFile string `json:"crl,omitempty" yaml:"crl,omitempty"`

	// OCSPFile specifies location of the OCSP response
	OCSPFile string `json:"ocsp,omitempty" yaml:"ocsp,omitempty"`

	// CipherSuites allows to speciy Cipher suites
	CipherSuites []string `json:"cipher_suites,omitempty" yaml:"cipher_suites,omitempty"`

	// ClientCertAuth controls client auth
	ClientCertAuth *bool `json:"client_cert_auth,omitempty" yaml:"client_cert_auth,omitempty"`
}

// SwaggerCfg specifies the configuration for Swagger
type SwaggerCfg struct {
	// Enabled allows Swagger
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Files is a map of service name to location
	Files map[string]string `json:"files" yaml:"files"`
}

// CORS contains configuration for CORS.
type CORS struct {

	// Enabled specifies if the CORS is enabled.
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`

	// MaxAge indicates how long (in seconds) the results of a preflight request can be cached.
	MaxAge int `json:"max_age,omitempty" yaml:"max_age,omitempty"`

	// AllowedOrigins is a list of origins a cross-domain request can be executed from.
	AllowedOrigins []string `json:"allowed_origins,omitempty" yaml:"allowed_origins,omitempty"`

	// AllowedMethods is a list of methods the client is allowed to use with cross-domain requests.
	AllowedMethods []string `json:"allowed_methods,omitempty" yaml:"allowed_methods,omitempty"`

	// AllowedHeaders is list of non simple headers the client is allowed to use with cross-domain requests.
	AllowedHeaders []string `json:"allowed_headers,omitempty" yaml:"allowed_headers,omitempty"`

	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS API specification.
	ExposedHeaders []string `json:"exposed_headers,omitempty" yaml:"exposed_headers,omitempty"`

	// AllowCredentials indicates whether the request can include user credentials.
	AllowCredentials *bool `json:"allow_credentials,omitempty" yaml:"allow_credentials,omitempty"`

	// OptionsPassthrough instructs preflight to let other potential next handlers to process the OPTIONS method.
	OptionsPassthrough *bool `json:"options_pass_through,omitempty" yaml:"options_pass_through,omitempty"`

	// Debug flag adds additional output to debug server side CORS issues.
	Debug *bool `json:"debug,omitempty" yaml:"debug,omitempty"`
}

// ParseListenURLs constructs a list of listen peers URLs
func (c *Config) ParseListenURLs() ([]*url.URL, error) {
	return netutil.ParseURLs(c.ListenURLs)
}

// Empty returns true if TLS info is empty
func (info *TLSInfo) Empty() bool {
	return info == nil || info.CertFile == "" || info.KeyFile == ""
}

// GetClientCertAuth controls client auth
func (info *TLSInfo) GetClientCertAuth() bool {
	return info.ClientCertAuth != nil && *info.ClientCertAuth
}

func (info *TLSInfo) String() string {
	if info == nil {
		return ""
	}
	return fmt.Sprintf("cert=%s, key=%s, trusted-ca=%s, client-cert-auth=%v, crl-file=%s",
		info.CertFile, info.KeyFile, info.TrustedCAFile, info.GetClientCertAuth(), info.CRLFile)
}

// GetEnabled specifies if the CORS is enabled.
func (c *CORS) GetEnabled() bool {
	return c != nil && c.Enabled != nil && *c.Enabled
}

// GetDebug flag adds additional output to debug server side CORS issues.
func (c *CORS) GetDebug() bool {
	return c != nil && c.Debug != nil && *c.Debug
}

// GetAllowCredentials flag
func (c *CORS) GetAllowCredentials() bool {
	return c != nil && c.AllowCredentials != nil && *c.AllowCredentials
}

// GetOptionsPassthrough flag
func (c *CORS) GetOptionsPassthrough() bool {
	return c != nil && c.OptionsPassthrough != nil && *c.OptionsPassthrough
}

// RateLimit contains configuration for Rate Limititing.
type RateLimit struct {
	// Enabled specifies if the Rate Limititing is enabled.
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// RequestsPerSecond specifies the maximum number of requests per second.
	RequestsPerSecond int `json:"requests_per_second,omitempty" yaml:"requests_per_second,omitempty"`
	// ExpirationTTL specifies the TTL for token bucket, default 10 mins
	ExpirationTTL time.Duration `json:"expiration_ttl,omitempty" yaml:"expiration_ttl,omitempty"`
	// HeadersIPLookups, default is  "X-Forwarded-For", "X-Real-IP" or "RemoteAddr".
	HeadersIPLookups []string `json:"headers_ip_lookups,omitempty" yaml:"headers_ip_lookups,omitempty"`
	// Metods, can be: "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS".
	Metods []string `json:"metods,omitempty" yaml:"metods,omitempty"`
}

// GetEnabled specifies if the Rate Limititing is enabled.
func (c *RateLimit) GetEnabled() bool {
	return c != nil && c.Enabled != nil && *c.Enabled
}
