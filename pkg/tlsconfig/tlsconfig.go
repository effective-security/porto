package tlsconfig

import (
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "tlsconfig")

// DefaultMinVersion is the tls.Config.MinVersion the constructors set: TLS
// 1.3. It is the only version that can authenticate with an ML-DSA
// certificate; SetMinVersion lowers a config to TLS 1.2 for older peers.
const DefaultMinVersion = tls.VersionTLS13

// tlsVersionNames maps the accepted spellings of a minimum TLS version,
// lower-cased and without spaces, to the crypto/tls constant.
var tlsVersionNames = map[string]uint16{
	"1.2":    tls.VersionTLS12,
	"tls1.2": tls.VersionTLS12,
	"1.3":    tls.VersionTLS13,
	"tls1.3": tls.VersionTLS13,
}

// ParseTLSVersion returns the crypto/tls version constant for a configured
// minimum version: "1.2", "1.3", "TLS1.2", "TLS 1.3" and so on, ignoring case
// and spaces. An empty string is DefaultMinVersion. TLS 1.0 and 1.1 and
// unknown names return an error.
func ParseTLSVersion(name string) (uint16, error) {
	if name == "" {
		return DefaultMinVersion, nil
	}
	key := strings.ToLower(strings.ReplaceAll(name, " ", ""))
	if v, ok := tlsVersionNames[key]; ok {
		return v, nil
	}
	return 0, errors.Errorf("unsupported TLS version %q: use 1.2 or 1.3", name)
}

// SetMinVersion sets cfg.MinVersion to version, or to DefaultMinVersion when
// version is zero. Only tls.VersionTLS12 and tls.VersionTLS13 are accepted.
// It returns an error, leaving cfg unchanged, when a version below TLS 1.3
// is combined with an ML-DSA certificate in cfg.Certificates: Go signs with
// ML-DSA only in TLS 1.3, and a TLS 1.2 handshake with such a certificate
// fails with an internal error alert. A certificate installed later through
// GetCertificate (a reloader rotating to an ML-DSA pair) is not checked, so
// keep TLS 1.3 when a rotation to ML-DSA is planned. A nil cfg is an error.
func SetMinVersion(cfg *tls.Config, version uint16) error {
	if cfg == nil {
		return errors.New("tls: config is nil")
	}
	if version == 0 {
		version = DefaultMinVersion
	}
	switch version {
	case tls.VersionTLS12, tls.VersionTLS13:
	default:
		return errors.Errorf("unsupported TLS minimum version 0x%04x: use TLS 1.2 or 1.3", version)
	}
	if version < tls.VersionTLS13 {
		for i := range cfg.Certificates {
			if IsMLDSACertificate(&cfg.Certificates[i]) {
				return errors.New("tls: ML-DSA certificates require TLS 1.3 as the minimum version")
			}
		}
	}
	cfg.MinVersion = version
	return nil
}

// IsMLDSACertificate reports whether the pair's leaf has an ML-DSA public
// key. It reads Leaf when set, else the public key of the private key (a
// crypto.Signer, so an HSM or KMS wrapper of an ML-DSA key is recognised
// too), and is false for a nil pair or one without a parsed leaf and a
// non-signer key.
func IsMLDSACertificate(cert *tls.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.Leaf != nil {
		_, ok := cert.Leaf.PublicKey.(*mldsa.PublicKey)
		return ok
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return false
	}
	_, ok = signer.Public().(*mldsa.PublicKey)
	return ok
}

// NewServerTLSFromFiles builds a server tls.Config (MinVersion TLS 1.3, ALPN
// h2/http1.1) from PEM files. certFile and keyFile are required; an OCSP staple
// is loaded from "<cert basename>.ocsp" if present. rootsFile (optional) is
// used as both RootCAs and ClientCAs; caFile (optional) overrides ClientCAs.
// When both are empty the OS roots are used and client certificates cannot be
// verified. clientauthType is applied as-is. CA files must contain at least
// one valid certificate. The returned config has
// no GetCertificate; pair it with KeypairReloader for rotation. Use
// SetMinVersion to admit TLS 1.2 clients; an ML-DSA certificate needs TLS 1.3.
func NewServerTLSFromFiles(certFile, keyFile, rootsFile, caFile string, clientauthType tls.ClientAuthType) (*tls.Config, error) {
	tlscert, err := LoadX509KeyPairWithOCSP(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	var roots *x509.CertPool

	if rootsFile != "" {
		var err error
		roots, err = loadCertPool(rootsFile)
		if err != nil {
			return nil, err
		}
	}

	cfg := &tls.Config{
		MinVersion:   DefaultMinVersion,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{*tlscert},
		ClientAuth:   clientauthType,
		ClientCAs:    roots,
		RootCAs:      roots,
	}
	if caFile != "" {
		cfg.ClientCAs, err = loadCertPool(caFile)
		if err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// NewClientTLSFromFiles builds a client tls.Config (MinVersion TLS 1.3, ALPN
// h2/http1.1) from PEM files. rootsFile (optional) sets RootCAs; when empty
// the OS roots are used. certFile/keyFile (optional) set the client
// certificate for mutual TLS. The certificate is loaded once; use
// NewClientTLSWithReloader for rotation. Use SetMinVersion to reach servers
// limited to TLS 1.2; an ML-DSA client certificate needs TLS 1.3.
func NewClientTLSFromFiles(certFile, keyFile, rootsFile string) (*tls.Config, error) {
	var roots *x509.CertPool

	if rootsFile != "" {
		var err error
		roots, err = loadCertPool(rootsFile)
		if err != nil {
			return nil, err
		}
	}

	cfg := &tls.Config{
		MinVersion: DefaultMinVersion,
		NextProtos: []string{"h2", "http/1.1"},
		//Certificates: []tls.Certificate{tlscert},
		ClientCAs: roots,
		RootCAs:   roots,
	}

	if certFile != "" {
		tlscert, err := LoadX509KeyPairWithOCSP(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		if tlscert.Leaf == nil && len(tlscert.Certificate) > 0 {
			tlscert.Leaf, err = x509.ParseCertificate(tlscert.Certificate[0])
			if err != nil {
				logger.KV(xlog.WARNING, "reason", "ParseCertificate", "err", err)
			}
		}

		cfg.Certificates = []tls.Certificate{*tlscert}
	}

	return cfg, nil
}

func loadCertPool(file string) (*x509.CertPool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read CA file %s", file)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.Errorf("CA file %s contains no valid certificates", file)
	}
	return pool, nil
}

// NewClientTLSWithReloader is NewClientTLSFromFiles plus a KeypairReloader
// wired as GetClientCertificate, polling every checkInterval. certFile and
// keyFile are required. The caller must Close the returned reloader.
func NewClientTLSWithReloader(certFile, keyFile, rootsFile string, checkInterval time.Duration) (*tls.Config, *KeypairReloader, error) {
	tlsCfg, err := NewClientTLSFromFiles(certFile, keyFile, rootsFile)
	if err != nil {
		return nil, nil, err
	}

	tlsloader, err := NewKeypairReloader("", certFile, keyFile, checkInterval)
	if err != nil {
		return nil, nil, err
	}
	tlsCfg.GetClientCertificate = tlsloader.GetClientCertificateFunc()

	return tlsCfg, tlsloader, nil
}

// NewHTTPTransportWithReloader returns an HTTPTransport with a fixed TLS
// client config that obtains the current certificate for each handshake.
// Reloads close idle connections so new dials use the new pair. The supplied
// transport is cloned before use. When HTTPUserTransport is nil a clone of
// http.DefaultTransport with 100 max idle/per-host connections is used.
// The caller must Close the returned transport to stop the reloader.
func NewHTTPTransportWithReloader(
	certFile, keyFile, rootsFile string,
	checkInterval time.Duration,
	HTTPUserTransport *http.Transport) (*HTTPTransport, error) {

	transport := HTTPUserTransport
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport)
	}
	transport = transport.Clone()
	if HTTPUserTransport == nil {
		transport.MaxIdleConnsPerHost = 100
		transport.MaxConnsPerHost = 100
		transport.MaxIdleConns = 100
	}

	tlsCfg, err := NewClientTLSFromFiles(certFile, keyFile, rootsFile)
	if err != nil {
		return nil, err
	}

	tlsloader, err := NewKeypairReloader("", certFile, keyFile, checkInterval)
	if err != nil {
		return nil, err
	}
	tlsCfg.Certificates = nil
	tlsCfg.GetClientCertificate = tlsloader.GetClientCertificateFunc()
	transport.TLSClientConfig = tlsCfg

	tripper := &HTTPTransport{
		transport: transport,
		reloader:  tlsloader,
	}

	tlsloader.OnReload(func(tlscert *tls.Certificate) {
		logger.KV(xlog.NOTICE, "reason", "onReload", "cn", tlscert.Leaf.Subject.CommonName, "expires", tlscert.Leaf.NotAfter.Format(time.RFC3339))

		tripper.transport.CloseIdleConnections()
	})

	return tripper, nil
}

// HTTPTransport is an http.RoundTripper that uses the current client
// certificate for each new TLS handshake. Create it with
// NewHTTPTransportWithReloader.
type HTTPTransport struct {
	transport *http.Transport
	reloader  *KeypairReloader
	lock      sync.Mutex
}

// RoundTrip forwards the request. Errors are returned with a stack trace attached.
func (t *HTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return resp, nil
}

// Close stops the certificate reloader and closes idle connections on the
// wrapped transport. It returns an error on a second call.
func (t *HTTPTransport) Close() error {
	t.lock.Lock()
	if t.reloader == nil {
		t.lock.Unlock()
		return errors.New("already closed")
	}
	reloader := t.reloader
	t.reloader = nil
	t.lock.Unlock()
	err := reloader.Close()
	t.transport.CloseIdleConnections()
	return err
}

var _ http.RoundTripper = (*HTTPTransport)(nil)
