package transport

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/crlcache"
	"github.com/effective-security/porto/pkg/tlsconfig"
)

// TLSInfo provides TLS configuration
type TLSInfo struct {
	CertFile            string
	KeyFile             string
	ClientCAFile        string
	TrustedCAFile       string
	ClientAuthType      tls.ClientAuthType
	CRLVerifier         crlcache.Verifier
	InsecureSkipVerify  bool
	SkipClientSANVerify bool

	// ServerName ensures the cert matches the given host in case of discovery / virtual hosting
	ServerName string

	// HandshakeFailure is optionally called when a connection fails to handshake. The
	// connection will be closed immediately afterwards.
	HandshakeFailure func(*tls.Conn, error)

	// CipherSuites is a list of supported cipher suites.
	// If empty, Go auto-populates it by default.
	// Note that cipher suites are prioritized in the given order.
	CipherSuites []string

	// AllowedCN is a CN which must be provided by a client.
	AllowedCN string

	// AllowedHostname is an IP address or hostname that must match the TLS
	// certificate provided by a client.
	AllowedHostname string

	// EmptyCN indicates that the cert must have empty CN.
	// If true, ClientConfig() will return an error for a cert with non empty CN.
	EmptyCN bool

	tlsCfg      *tls.Config
	tlsReloader *tlsconfig.KeypairReloader
}

func (info *TLSInfo) String() string {
	return fmt.Sprintf("cert=%s, key=%s, trusted-ca=%s, client-ca=%s, client-cert-auth=%d",
		info.CertFile, info.KeyFile, info.TrustedCAFile, info.ClientCAFile, int(info.ClientAuthType))
}

// Empty returns true if TLS info is empty
func (info *TLSInfo) Empty() bool {
	return info.CertFile == "" || info.KeyFile == ""
}

// Close the resources
func (info *TLSInfo) Close() {
	if info.tlsReloader != nil {
		info.tlsReloader.Close()
		info.tlsReloader = nil
	}
	if info.tlsCfg != nil {
		info.tlsCfg = nil
	}
}

// Config returns tls.Config
func (info *TLSInfo) Config() *tls.Config {
	return info.tlsCfg
}

// ServerTLSWithReloader returns tls.Config with reloader
func (info *TLSInfo) ServerTLSWithReloader() (*tls.Config, error) {
	var err error

	if info.tlsCfg != nil {
		return info.tlsCfg, nil
	}

	info.tlsCfg, err = tlsconfig.NewServerTLSFromFiles(
		info.CertFile,
		info.KeyFile,
		info.TrustedCAFile,
		info.ClientCAFile,
		info.ClientAuthType)
	if err != nil {
		return nil, err
	}

	if len(info.tlsCfg.Certificates) > 0 &&
		info.tlsCfg.Certificates[0].Leaf != nil &&
		info.tlsCfg.Certificates[0].Leaf.NotAfter.Before(time.Now()) {
		return nil, errors.New("tls: certificate has expired")
	}

	if err = tlsconfig.UpdateCipherSuites(info.tlsCfg, info.CipherSuites); err != nil {
		return nil, err
	}

	info.tlsReloader, err = tlsconfig.NewKeypairReloader(
		"",
		info.CertFile,
		info.KeyFile,
		5*time.Minute)
	if err != nil {
		return nil, err
	}

	//  TODO: tlsloader.WithOCSPStaple(cfg.OCSPFile)
	info.tlsCfg.GetCertificate = info.tlsReloader.GetKeypairFunc()

	return info.tlsCfg, nil
}
