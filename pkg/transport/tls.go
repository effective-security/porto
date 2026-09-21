package transport

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/crlcache"
	"github.com/effective-security/porto/pkg/tlsconfig"
)

// TLSInfo is the file-based TLS configuration of a server listener.
// ServerTLSWithReloader builds and caches the tls.Config; Close releases the
// reloader. It is not safe for concurrent use while being initialized.
//
// Fields that are read by this package: CertFile, KeyFile, TrustedCAFile,
// ClientCAFile, ClientAuthType, CipherSuites, CRLVerifier, HandshakeFailure.
// InsecureSkipVerify, SkipClientSANVerify, ServerName, AllowedCN,
// AllowedHostname and EmptyCN are currently not enforced.
type TLSInfo struct {
	// CertFile and KeyFile are the PEM server certificate chain and key; required.
	CertFile string
	KeyFile  string
	// ClientCAFile is a PEM bundle used to verify client certificates.
	// When empty, TrustedCAFile is used for that purpose as well.
	ClientCAFile string
	// TrustedCAFile is a PEM bundle used as RootCAs (and ClientCAs when
	// ClientCAFile is empty). When empty, OS roots are used.
	TrustedCAFile string
	// ClientAuthType is passed to tls.Config.ClientAuth (default NoClientCert).
	ClientAuthType tls.ClientAuthType
	// CRLVerifier, when set, is consulted by NewTLSListener for every
	// certificate in the client's verified chains; a Revoked status rejects
	// the connection, errors and Unknown are logged and allowed.
	CRLVerifier crlcache.Verifier
	// InsecureSkipVerify is not used by this package.
	InsecureSkipVerify bool
	// SkipClientSANVerify is not used by this package.
	SkipClientSANVerify bool

	// ServerName ensures the cert matches the given host in case of discovery / virtual hosting.
	// It is not used by this package.
	ServerName string

	// HandshakeFailure is optionally called when a connection fails to handshake. The
	// connection will be closed immediately afterwards.
	HandshakeFailure func(*tls.Conn, error)

	// CipherSuites is a list of supported cipher suites.
	// If empty, Go auto-populates it by default.
	// Note that cipher suites are prioritized in the given order.
	CipherSuites []string

	// AllowedCN is a CN which must be provided by a client.
	// It is not enforced by this package.
	AllowedCN string

	// AllowedHostname is an IP address or hostname that must match the TLS
	// certificate provided by a client. It is not enforced by this package.
	AllowedHostname string

	// EmptyCN indicates that the cert must have empty CN.
	// It is not enforced by this package.
	EmptyCN bool

	tlsCfg      *tls.Config
	tlsReloader *tlsconfig.KeypairReloader
}

// String returns a one-line summary of the file paths and client auth mode.
func (info *TLSInfo) String() string {
	return fmt.Sprintf("cert=%s, key=%s, trusted-ca=%s, client-ca=%s, client-cert-auth=%d",
		info.CertFile, info.KeyFile, info.TrustedCAFile, info.ClientCAFile, int(info.ClientAuthType))
}

// Empty reports whether CertFile or KeyFile is missing, i.e. TLS cannot be served.
func (info *TLSInfo) Empty() bool {
	return info.CertFile == "" || info.KeyFile == ""
}

// Close stops the certificate reloader and drops the cached tls.Config.
// It is safe to call when ServerTLSWithReloader was never called.
func (info *TLSInfo) Close() {
	if info.tlsReloader != nil {
		info.tlsReloader.Close()
		info.tlsReloader = nil
	}
	if info.tlsCfg != nil {
		info.tlsCfg = nil
	}
}

// Config returns the tls.Config built by ServerTLSWithReloader, or nil
// if it has not been called (or after Close).
func (info *TLSInfo) Config() *tls.Config {
	return info.tlsCfg
}

// ServerTLSWithReloader builds (once) and returns the server tls.Config from
// the files, applies CipherSuites, and installs a KeypairReloader polling
// every 5 minutes as GetCertificate. It returns an error if the certificate
// has already expired. Subsequent calls return the cached config.
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
