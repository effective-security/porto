package gserver

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/restserver/authz"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/x/netutil"
)

const (
	// corsWildcardOrigin is the CORS.AllowedOrigins entry that allows every origin.
	corsWildcardOrigin = "*"
	// corsHeaderPrefix is the lower-case prefix of CORS response header names,
	// which an enabled CORS block owns.
	corsHeaderPrefix = "access-control-"
)

// Config is the server configuration passed to Start. It is usually
// unmarshalled from YAML/JSON; the yaml and json tags give the field names.
type Config struct {
	// DebugLogs enables verbose per-request debug logging in the gRPC/HTTP mux.
	DebugLogs bool `json:"debug_logs" yaml:"debug_logs"`

	// Description provides description of the server
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Disabled specifies if the service is disabled
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`

	// ClientURL is the public URL exposed to clients
	ClientURL string `json:"client_url" yaml:"client_url"`

	// ListenURLs is the list of URLs to listen on. Supported schemes are
	// http, https, unix and unixs; a URL without scheme defaults to https when
	// ServerTLS is set. URLs with the same address share one listener.
	ListenURLs []string `json:"listen_urls" yaml:"listen_urls"`

	// ServerTLS provides the TLS config for the server; required for https/unixs URLs.
	ServerTLS *TLSInfo `json:"server_tls,omitempty" yaml:"server_tls,omitempty"`

	// SkipLogPaths if set, specifies a list of paths to not log.
	// this can be used for /v1/status/node or /metrics
	SkipLogPaths []telemetry.LoggerSkipPath `json:"logger_skip_paths,omitempty" yaml:"logger_skip_paths,omitempty"`

	// PromGrpc adds the go-grpc-prometheus unary and stream interceptors.
	PromGrpc bool `json:"prom_grpc" yaml:"prom_grpc"`

	// Services is the list of service names to enable; each must have a
	// ServiceFactory registered in the map passed to Start.
	Services []string `json:"services" yaml:"services"`

	// IdentityMap configures how callers are authenticated and mapped to roles
	// (see gserver/roles). When nil an empty map is used and all callers are guests.
	IdentityMap *roles.IdentityMap `json:"identity_map" yaml:"identity_map"`

	// Authz configures path/role based authorization (see restserver/authz).
	// It is only activated when at least one of Allow, AllowAny or AllowAnyRole is set.
	Authz *authz.Config `json:"authz" yaml:"authz"`

	// CORS contains configuration for CORS.
	CORS *CORS `json:"cors,omitempty" yaml:"cors,omitempty"`

	// RateLimit contains configuration for the rate limiter
	RateLimit *RateLimit `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`

	// TrustedProxyCIDRs permits these socket peers to supply forwarding headers.
	// By default, only the socket address is used for client IP and scheme.
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs,omitempty" yaml:"trusted_proxy_cidrs,omitempty"`

	// Timeout settings
	Timeout struct {
		// Request is how long Close waits for in-flight requests to finish
		// before forcing shutdown; default 3s.
		Request time.Duration `json:"request,omitempty" yaml:"request,omitempty"`
	} `json:"timeout" yaml:"timeout"`

	// KeepAlive settings
	KeepAlive KeepAliveCfg `json:"keep_alive" yaml:"keep_alive"`

	// MaxRecvMsgSize sets the maximum gRPC message size a client can send;
	// the MaxRecvMsgSize Option takes precedence when set.
	MaxRecvMsgSize int `json:"max_recv_msg_size,omitempty" yaml:"max_recv_msg_size,omitempty"`

	// MaxSendMsgSize sets the maximum gRPC message size the server can send;
	// the MaxSendMsgSize Option takes precedence when set.
	MaxSendMsgSize int `json:"max_send_msg_size,omitempty" yaml:"max_send_msg_size,omitempty"`

	// HTTPHeaders are static response headers set on every response served
	// by TLS listeners (they are not applied on plain http listeners).
	// While CORS is enabled, Access-Control-* names are rejected (see
	// Validate): the CORS block owns those headers.
	HTTPHeaders map[string]string `json:"http_headers,omitempty" yaml:"http_headers,omitempty"`
}

// KeepAliveCfg configures gRPC keepalive. MinTime sets the enforcement
// policy; Interval and Timeout are only applied when both are positive.
// MaxConnectionIdle is always 5 minutes.
type KeepAliveCfg struct {
	// MinTime is the minimum interval that a client should wait before pinging server.
	MinTime time.Duration `json:"min_time,omitempty" yaml:"min_time,omitempty"`

	// Interval is the frequency of server-to-client ping to check if a connection is alive.
	Interval time.Duration `json:"interval,omitempty" yaml:"interval,omitempty"`

	// Timeout is the additional duration of wait before closing a non-responsive connection, use 0 to disable.
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// TLSInfo is the server TLS configuration. Cert and key files are watched
// and reloaded by pkg/transport; CRLFile and OCSPFile are currently not used.
type TLSInfo struct {
	// CertFile specifies location of the cert
	CertFile string `json:"cert,omitempty" yaml:"cert,omitempty"`

	// KeyFile specifies location of the key
	KeyFile string `json:"key,omitempty" yaml:"key,omitempty"`

	// TrustedCAFile specifies location of the trusted root CA bundle
	TrustedCAFile string `json:"trusted_ca,omitempty" yaml:"trusted_ca,omitempty"`

	// ClientCAFile specifies location of the CA bundle used to verify client certificates
	ClientCAFile string `json:"client_ca,omitempty" yaml:"client_ca,omitempty"`

	// CRLFile specifies location of the CRL
	CRLFile string `json:"crl,omitempty" yaml:"crl,omitempty"`

	// OCSPFile specifies location of the OCSP response
	OCSPFile string `json:"ocsp,omitempty" yaml:"ocsp,omitempty"`

	// CipherSuites optionally restricts the TLS cipher suites (by name)
	CipherSuites []string `json:"cipher_suites,omitempty" yaml:"cipher_suites,omitempty"`

	// ClientCertAuth, when true, requires and verifies a client certificate;
	// otherwise a client certificate is verified only if presented.
	ClientCertAuth *bool `json:"client_cert_auth,omitempty" yaml:"client_cert_auth,omitempty"`
}

// SwaggerCfg specifies the configuration for Swagger. It is not used by
// gserver itself and is provided for services that serve Swagger files.
type SwaggerCfg struct {
	// Enabled allows Swagger
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Files is a map of service name to location
	Files map[string]string `json:"files" yaml:"files"`
}

// CORS configures cross-origin handling. When enabled the REST handler is
// wrapped with github.com/rs/cors; AllowedOrigins, ExposedHeaders and
// AllowCredentials are also applied to gRPC-Web responses on TLS listeners.
// Both match origins the same way, including rs/cors origin patterns. Use
// AllowedOrigins with "*" to allow every origin; an empty list allows none.
// "*" cannot be combined with AllowCredentials: Start rejects that
// configuration (see Validate).
//
// For REST, CORS only controls whether a browser may read the response; it is
// not request or CSRF protection. A REST request from a disallowed origin
// still reaches its handler and only lacks CORS response headers, and a
// disallowed preflight gets no allow headers. gRPC-Web rejects a request from
// a disallowed origin with HTTP 403 before the service is called.
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
	// It requires explicit AllowedOrigins or origin patterns; "*" is rejected.
	AllowCredentials *bool `json:"allow_credentials,omitempty" yaml:"allow_credentials,omitempty"`

	// OptionsPassthrough instructs preflight to let other potential next handlers to process the OPTIONS method.
	OptionsPassthrough *bool `json:"options_pass_through,omitempty" yaml:"options_pass_through,omitempty"`

	// Debug flag adds additional output to debug server side CORS issues.
	Debug *bool `json:"debug,omitempty" yaml:"debug,omitempty"`
}

// Validate returns an error for a configuration Start cannot serve safely: an
// invalid TrustedProxyCIDRs entry, an invalid CORS block (see CORS.Validate)
// or, while CORS is enabled, an HTTPHeaders entry that would set an
// Access-Control-* header outside the CORS policy. Start runs the same checks.
func (c *Config) Validate() error {
	_, err := c.validate()
	return err
}

// validate implements Validate and returns the parsed trusted proxy policy,
// so Start does not parse TrustedProxyCIDRs a second time.
func (c *Config) validate() (*identity.TrustedProxies, error) {
	trustedProxies, err := identity.ParseTrustedProxies(c.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	if err := c.CORS.Validate(); err != nil {
		return nil, err
	}
	if c.CORS.GetEnabled() {
		for _, name := range slices.Sorted(maps.Keys(c.HTTPHeaders)) {
			if strings.HasPrefix(strings.ToLower(name), corsHeaderPrefix) {
				return nil, errors.Newf("http_headers: %q cannot be set while cors is enabled; configure it in the cors block", name)
			}
		}
	}
	return trustedProxies, nil
}

// ParseListenURLs parses ListenURLs into URLs, returning an error for any
// malformed entry.
func (c *Config) ParseListenURLs() ([]*url.URL, error) {
	return netutil.ParseURLs(c.ListenURLs)
}

// Empty returns true if the receiver is nil or either CertFile or KeyFile is unset.
func (info *TLSInfo) Empty() bool {
	return info == nil || info.CertFile == "" || info.KeyFile == ""
}

// GetClientCertAuth returns true when ClientCertAuth is set and true.
func (info *TLSInfo) GetClientCertAuth() bool {
	return info.ClientCertAuth != nil && *info.ClientCertAuth
}

// String returns a loggable summary of the TLS file locations; safe on a nil receiver.
func (info *TLSInfo) String() string {
	if info == nil {
		return ""
	}
	return fmt.Sprintf("cert=%s, key=%s, trusted-ca=%s, client-cert-auth=%v, crl-file=%s",
		info.CertFile, info.KeyFile, info.TrustedCAFile, info.GetClientCertAuth(), info.CRLFile)
}

// GetEnabled returns true when CORS is configured and enabled; safe on a nil receiver.
func (c *CORS) GetEnabled() bool {
	return c != nil && c.Enabled != nil && *c.Enabled
}

// GetDebug returns the Debug flag; safe on a nil receiver.
func (c *CORS) GetDebug() bool {
	return c != nil && c.Debug != nil && *c.Debug
}

// GetAllowCredentials returns the AllowCredentials flag; safe on a nil receiver.
func (c *CORS) GetAllowCredentials() bool {
	return c != nil && c.AllowCredentials != nil && *c.AllowCredentials
}

// Validate returns an error when an enabled CORS block combines the "*" origin
// with AllowCredentials, which would let every web origin read credentialed
// responses. A nil or disabled CORS is valid. Start calls it through
// Config.Validate.
func (c *CORS) Validate() error {
	if c.GetEnabled() && c.GetAllowCredentials() && slices.Contains(c.AllowedOrigins, corsWildcardOrigin) {
		return errors.New(`cors: allowed_origins "*" cannot be combined with allow_credentials; list explicit origins`)
	}
	return nil
}

// GetOptionsPassthrough returns the OptionsPassthrough flag; safe on a nil receiver.
func (c *CORS) GetOptionsPassthrough() bool {
	return c != nil && c.OptionsPassthrough != nil && *c.OptionsPassthrough
}

// RateLimit configures the per-client token bucket rate limiter
// (github.com/didip/tollbooth) that wraps the HTTP handler.
type RateLimit struct {
	// Enabled specifies if rate limiting is enabled.
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// RequestsPerSecond specifies the maximum number of requests per second.
	RequestsPerSecond int `json:"requests_per_second,omitempty" yaml:"requests_per_second,omitempty"`
	// ExpirationTTL specifies the TTL for token bucket, default 10 mins
	ExpirationTTL time.Duration `json:"expiration_ttl,omitempty" yaml:"expiration_ttl,omitempty"`
	// HeadersIPLookups lists the sources used to identify the client, in order;
	// default is the trusted client address derived from the socket peer and
	// TrustedProxyCIDRs. Explicit header lookups can be spoofed and should be
	// configured only when the deployment guarantees they are overwritten.
	HeadersIPLookups []string `json:"headers_ip_lookups,omitempty" yaml:"headers_ip_lookups,omitempty"`
	// Metods (sic) restricts limiting to the listed HTTP methods, e.g. "GET", "POST";
	// empty means all methods.
	Metods []string `json:"metods,omitempty" yaml:"metods,omitempty"`
}

// GetEnabled returns true when rate limiting is configured and enabled; safe on a nil receiver.
func (c *RateLimit) GetEnabled() bool {
	return c != nil && c.Enabled != nil && *c.Enabled
}
