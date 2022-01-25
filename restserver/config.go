package restserver

import (
	"os"
	"strings"
)

// TLSInfoConfig contains configuration info for the TLS
type TLSInfoConfig interface {
	// GetCertFile returns location of the cert
	GetCertFile() string
	// GetKeyFile returns location of the key
	GetKeyFile() string
	// GetTrustedCAFile specifies location of the Trusted CA file
	GetTrustedCAFile() string
	// GetClientCertAuth controls client auth
	GetClientCertAuth() *bool
}

// Config provides interface for the server configurarion
type Config interface {
	// GetServerName provides name of the server: WebAPI|Admin etc
	GetServerName() string
	// GetBindAddr provides the address that the HTTPS server should be listening on
	GetBindAddr() string
	// GetPublicURL is the FQ name of the VIP to the cluster that clients use to connect
	GetPublicURL() string
	// Services is a list of services to enable for this HTTP Service
	GetServices() []string
}

// GetPort returns the port from HTTP bind address,
// or standard HTTPS 443 port, if it's not specified in the config
func GetPort(bindAddr string) string {
	i := strings.LastIndex(bindAddr, ":")
	if i >= 0 {
		return bindAddr[i+1:]
	}
	return "443"
}

// GetHostName returns Hostname from HTTP bind address,
// or OS Hostname, if it's not specified in the config
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
