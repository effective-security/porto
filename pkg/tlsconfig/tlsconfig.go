package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "tlsconfig")

// NewServerTLSFromFiles builds a server tls.Config (MinVersion TLS 1.2, ALPN
// h2/http1.1) from PEM files. certFile and keyFile are required; an OCSP staple
// is loaded from "<cert basename>.ocsp" if present. rootsFile (optional) is
// used as both RootCAs and ClientCAs; caFile (optional) overrides ClientCAs.
// When both are empty the OS roots are used and client certificates cannot be
// verified. clientauthType is applied as-is. Files that contain no valid
// certificate produce an empty pool without error. The returned config has
// no GetCertificate; pair it with KeypairReloader for rotation.
func NewServerTLSFromFiles(certFile, keyFile, rootsFile, caFile string, clientauthType tls.ClientAuthType) (*tls.Config, error) {
	tlscert, err := LoadX509KeyPairWithOCSP(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	var roots *x509.CertPool

	if rootsFile != "" {
		rootsBytes, err := os.ReadFile(rootsFile)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM(rootsBytes)
	}

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{*tlscert},
		ClientAuth:   clientauthType,
		ClientCAs:    roots,
		RootCAs:      roots,
	}
	if caFile != "" {
		caBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		cfg.ClientCAs = x509.NewCertPool()
		cfg.ClientCAs.AppendCertsFromPEM(caBytes)
	}

	return cfg, nil
}

// NewClientTLSFromFiles builds a client tls.Config (MinVersion TLS 1.2, ALPN
// h2/http1.1) from PEM files. rootsFile (optional) sets RootCAs; when empty
// the OS roots are used. certFile/keyFile (optional) set the client
// certificate for mutual TLS. The certificate is loaded once; use
// NewClientTLSWithReloader for rotation.
func NewClientTLSFromFiles(certFile, keyFile, rootsFile string) (*tls.Config, error) {
	var roots *x509.CertPool

	if rootsFile != "" {
		rootsBytes, err := os.ReadFile(rootsFile)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM(rootsBytes)
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
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

// NewHTTPTransportWithReloader returns an HTTPTransport that installs a fresh
// TLS client config (with the reloaded certificate) on the underlying
// *http.Transport whenever the cert file changes, closing idle connections so
// new dials use it. When HTTPUserTransport is nil a clone of
// http.DefaultTransport with 100 max idle/per-host connections is used.
// The caller must Close the returned transport to stop the reloader.
func NewHTTPTransportWithReloader(
	certFile, keyFile, rootsFile string,
	checkInterval time.Duration,
	HTTPUserTransport *http.Transport) (*HTTPTransport, error) {

	transport := HTTPUserTransport
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
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

	tripper := &HTTPTransport{
		transport: transport,
		tlsConfig: tlsCfg,
		reloader:  tlsloader,
	}

	tlsloader.OnReload(func(tlscert *tls.Certificate) {
		logger.KV(xlog.NOTICE, "reason", "onReload", "cn", tlscert.Leaf.Subject.CommonName, "expires", tlscert.Leaf.NotAfter.Format(time.RFC3339))

		tripper.lock.Lock()
		tripper.tlsConfig = tripper.tlsConfig.Clone()
		tripper.tlsConfig.Certificates = []tls.Certificate{*tlscert}
		tripper.transport.CloseIdleConnections()
		tripper.lock.Unlock()
	})

	return tripper, nil
}

// HTTPTransport is an http.RoundTripper that re-applies its current
// TLSClientConfig to the wrapped *http.Transport on every request so that a
// reloaded client certificate takes effect. Create it with
// NewHTTPTransportWithReloader.
type HTTPTransport struct {
	transport *http.Transport
	tlsConfig *tls.Config
	reloader  *KeypairReloader
	lock      sync.RWMutex
}

// RoundTrip sets the current TLS config on the wrapped transport and forwards
// the request. Errors are returned with a stack trace attached.
func (t *HTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.lock.Lock()
	cfg := t.tlsConfig
	t.transport.TLSClientConfig = cfg
	t.lock.Unlock()

	resp, err := t.transport.RoundTrip(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return resp, nil
}

// Close stops the certificate reloader. It returns an error on a second call.
// The wrapped *http.Transport is left open.
func (t *HTTPTransport) Close() error {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if t.reloader == nil {
		return errors.New("already closed")
	}
	err := t.reloader.Close()
	t.reloader = nil
	return err
}

var _ http.RoundTripper = (*HTTPTransport)(nil)
