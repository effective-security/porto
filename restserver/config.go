package restserver

import (
	"os"
	"strings"
)

// TLSInfoConfig describes where a server's TLS material lives. It is the
// contract consumers' config structs satisfy to build a *tls.Config for New.
type TLSInfoConfig interface {
	// GetCertFile returns location of the cert
	GetCertFile() string
	// GetKeyFile returns location of the key
	GetKeyFile() string
	// GetTrustedCAFile specifies location of the Trusted CA file
	GetTrustedCAFile() string
	// GetClientCAFile specifies location of the client CA bundle file
	GetClientCAFile() string
	// GetClientCertAuth controls client auth
	GetClientCertAuth() *bool
}

// Config is the server configuration contract passed to New. Consumers
// typically satisfy it with a struct loaded from YAML/JSON.
type Config interface {
	// GetServerName provides name of the server: WebAPI|Admin etc
	GetServerName() string
	// GetBindAddr provides the address that the HTTPS server should be listening on
	GetBindAddr() string
	// GetPublicURL is the FQ name of the VIP to the cluster that clients use to connect
	GetPublicURL() string
	// GetServices returns the names of services to enable for this HTTP server
	GetServices() []string
}

// GetPort returns the port from an HTTP bind address ("host:port" or ":port"),
// or "443" when the address contains no colon. Unbracketed IPv6 literals
// without a port are not supported (the last group is returned).
func GetPort(bindAddr string) string {
	i := strings.LastIndex(bindAddr, ":")
	if i >= 0 {
		return bindAddr[i+1:]
	}
	return "443"
}

// GetHostName returns the host part of an HTTP bind address, or the OS
// hostname when the address has no host (for example ":8080").
func GetHostName(bindAddr string) string {
	hn := bindAddr
	i := strings.LastIndex(bindAddr, ":")
	if i >= 0 {
		hn = bindAddr[:i]
	}
	if hn == "" {
		hn, _ = os.Hostname()
	}
	return hn
}
