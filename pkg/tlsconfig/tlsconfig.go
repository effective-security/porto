package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "tlsconfig")

// NewServerTLSFromFiles will build a tls.Config from the supplied certificate, key
// and optional trust roots files, these files are all expected to be PEM encoded.
// The file paths are relative to the working directory if not specified in absolute
// format.
// caBundle is optional.
// rootsFile is optional, if not specified the standard OS CA roots will be used.
func NewServerTLSFromFiles(certFile, keyFile, rootsFile string, clientauthType tls.ClientAuthType) (*tls.Config, error) {
	tlscert, err := LoadX509KeyPairWithOCSP(certFile, keyFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var roots *x509.CertPool

	if rootsFile != "" {
		rootsBytes, err := ioutil.ReadFile(rootsFile)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM(rootsBytes)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{*tlscert},
		ClientAuth:   clientauthType,
		ClientCAs:    roots,
		RootCAs:      roots,
	}, nil
}

// NewClientTLSFromFiles will build a tls.Config from the supplied certificate, key
// and optional trust roots files, these files are all expected to be PEM encoded.
// The file paths are relative to the working directory if not specified in absolute
// format.
// caBundle is optional.
// rootsFile is optional, if not specified the standard OS CA roots will be used.
func NewClientTLSFromFiles(certFile, keyFile, rootsFile string) (*tls.Config, error) {
	var roots *x509.CertPool

	if rootsFile != "" {
		rootsBytes, err := ioutil.ReadFile(rootsFile)
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
			return nil, errors.WithStack(err)
		}
		if tlscert.Leaf == nil && len(tlscert.Certificate) > 0 {
			tlscert.Leaf, err = x509.ParseCertificate(tlscert.Certificate[0])
			if err != nil {
				logger.Warningf("reason=ParseCertificate, err=[%v]", err)
			}
		}

		cfg.Certificates = []tls.Certificate{*tlscert}
	}

	return cfg, nil
}

// NewClientTLSWithReloader is a wrapper around NewClientTLSFromFiles with NewKeypairReloader
func NewClientTLSWithReloader(certFile, keyFile, rootsFile string, checkInterval time.Duration) (*tls.Config, *KeypairReloader, error) {
	tlsCfg, err := NewClientTLSFromFiles(certFile, keyFile, rootsFile)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	tlsloader, err := NewKeypairReloader("", certFile, keyFile, checkInterval)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	tlsCfg.GetClientCertificate = tlsloader.GetClientCertificateFunc()

	return tlsCfg, tlsloader, nil
}

// NewHTTPTransportWithReloader creates an HTTPTransport based on a
// given Transport (or http.DefaultTransport).
func NewHTTPTransportWithReloader(
	certFile, keyFile, rootsFile string,
	checkInterval time.Duration,
	HTTPUserTransport *http.Transport) (*HTTPTransport, error) {

	transport := HTTPUserTransport
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport)
	}

	tlsCfg, err := NewClientTLSFromFiles(certFile, keyFile, rootsFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	tlsloader, err := NewKeypairReloader("", certFile, keyFile, checkInterval)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	tripper := &HTTPTransport{
		transport: transport,
		tlsConfig: tlsCfg,
		reloader:  tlsloader,
	}

	tlsloader.OnReload(func(tlscert *tls.Certificate) {
		logger.Noticef("reason=onReload, cn=%q, expires=%q",
			tlscert.Leaf.Subject.CommonName, tlscert.Leaf.NotAfter.Format(time.RFC3339))

		tripper.lock.Lock()
		tripper.tlsConfig = tripper.tlsConfig.Clone()
		tripper.tlsConfig.Certificates = []tls.Certificate{*tlscert}
		tripper.transport.CloseIdleConnections()
		tripper.lock.Unlock()
	})

	return tripper, nil
}

// HTTPTransport is an implementation of http.RoundTripper with an
// auto-updating TLSClientConfig.
type HTTPTransport struct {
	transport *http.Transport
	tlsConfig *tls.Config
	reloader  *KeypairReloader
	lock      sync.RWMutex
}

// RoundTrip implements the http.RoundTripper interface.
func (t *HTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.lock.Lock()
	cfg := t.tlsConfig
	t.transport.TLSClientConfig = cfg
	t.lock.Unlock()

	resp, err := t.transport.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Close will close the reloader and release its resources
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
