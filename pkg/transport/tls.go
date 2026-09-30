package transport

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/crlcache"
	"github.com/effective-security/porto/pkg/tlsconfig"
)

// reloadInterval is how often the server key pair files are polled.
const reloadInterval = 5 * time.Minute

// TLSInfo is the file-based TLS configuration of a server listener.
// ServerTLSWithReloader builds and caches the tls.Config; Close releases the
// reloader. It is not safe for concurrent use while being initialized.
//
// Client certificate policy beyond ClientAuthType and CRLVerifier (for
// example a required subject) is not configured here: call
// ServerTLSWithReloader first and set VerifyConnection on the returned
// config before the listener serves. Close drops the config, so a later
// ServerTLSWithReloader call returns a new one without it.
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

	// HandshakeFailure is optionally called when a connection fails to handshake. The
	// connection will be closed immediately afterwards.
	HandshakeFailure func(*tls.Conn, error)

	// HandshakeTimeout bounds each eager TLS handshake. Zero uses
	// limits.DefaultHandshakeTimeout; a negative duration disables the deadline.
	HandshakeTimeout time.Duration

	// CipherSuites optionally restricts the enabled TLS 1.2 cipher suites, by
	// crypto/tls name; if empty, Go uses its default list. The order is
	// ignored: Go picks the preferred mutually supported suite itself.
	// tlsconfig.UpdateCipherSuites rejects insecure and TLS 1.3 names.
	CipherSuites []string

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
// has already expired. Subsequent calls return the cached config. A call
// that fails caches nothing, so a later call loads the files again.
func (info *TLSInfo) ServerTLSWithReloader() (*tls.Config, error) {
	if info.tlsCfg != nil {
		return info.tlsCfg, nil
	}

	// Build into locals: info keeps no state from a failed attempt.
	cfg, err := tlsconfig.NewServerTLSFromFiles(
		info.CertFile,
		info.KeyFile,
		info.TrustedCAFile,
		info.ClientCAFile,
		info.ClientAuthType)
	if err != nil {
		return nil, err
	}

	if len(cfg.Certificates) > 0 &&
		cfg.Certificates[0].Leaf != nil &&
		cfg.Certificates[0].Leaf.NotAfter.Before(time.Now()) {
		return nil, errors.New("tls: certificate has expired")
	}

	if err = tlsconfig.UpdateCipherSuites(cfg, info.CipherSuites); err != nil {
		return nil, err
	}

	reloader, err := tlsconfig.NewKeypairReloader(
		"",
		info.CertFile,
		info.KeyFile,
		reloadInterval)
	if err != nil {
		return nil, err
	}

	//  TODO: tlsloader.WithOCSPStaple(cfg.OCSPFile)
	cfg.GetCertificate = reloader.GetKeypairFunc()
	// Go skips GetCertificate for clients without SNI when Certificates is set.
	cfg.Certificates = nil

	info.tlsCfg = cfg
	info.tlsReloader = reloader
	return cfg, nil
}
