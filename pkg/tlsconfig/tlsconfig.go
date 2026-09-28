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
// verified. clientauthType is applied as-is. CA files must contain at least
// one valid certificate. The returned config has
// no GetCertificate; pair it with KeypairReloader for rotation.
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
		MinVersion:   tls.VersionTLS12,
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

// NewClientTLSFromFiles builds a client tls.Config (MinVersion TLS 1.2, ALPN
// h2/http1.1) from PEM files. rootsFile (optional) sets RootCAs; when empty
// the OS roots are used. certFile/keyFile (optional) set the client
// certificate for mutual TLS. The certificate is loaded once; use
// NewClientTLSWithReloader for rotation.
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
