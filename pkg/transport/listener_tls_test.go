package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func TestNewTLSListener_Untrusted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tlsInfo := &TLSInfo{
		CertFile:      serverCertFile,
		KeyFile:       serverKeyFile,
		TrustedCAFile: serverRootFile,
		CRLVerifier:   verifier{status: ocsp.Good},
	}
	defer tlsInfo.Close()

	tlsln, err := NewTLSListener(ln, tlsInfo)
	require.NoError(t, err)

	fmt.Printf("listening on %v", tlsln.Addr().String())
	t.Logf("listening on %v", tlsln.Addr().String())

	router := restserver.NewRouter(notFoundHandler)

	srv := &http.Server{
		Handler:   router.Handler(),
		TLSConfig: tlsInfo.Config(),
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(tlsln)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		t.Logf("sending to %v", tlsln.Addr().String())
		res, err := http.Get("https://" + tlsln.Addr().String())
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "certificate signed by unknown authority")
			t.Logf("error from %v: %s", tlsln.Addr().String(), err.Error())
		}
		if res != nil {
			t.Logf("response code from %v: %d", tlsln.Addr().String(), res.StatusCode)
		}
	}()

	time.Sleep(3 * time.Second)
	tlsln.Close()
	wg.Wait()
}

func TestNewTLSListener_Trusted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tlsInfo := &TLSInfo{
		CertFile:      serverCertFile,
		KeyFile:       serverKeyFile,
		TrustedCAFile: serverRootFile,
		CRLVerifier:   verifier{status: ocsp.Good},
	}
	defer tlsInfo.Close()

	tlsln, err := NewTLSListener(ln, tlsInfo)
	require.NoError(t, err)

	fmt.Printf("listening on %v", tlsln.Addr().String())
	t.Logf("listening on %v", tlsln.Addr().String())

	router := restserver.NewRouter(notFoundHandler)

	srv := &http.Server{
		Handler:   router.Handler(),
		TLSConfig: tlsInfo.Config(),
	}

	clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", serverRootFile)
	require.NoError(t, err)

	client := retriable.New(retriable.WithTLS(clientTLS))
	require.NotNil(t, client)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(tlsln)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		t.Logf("sending to %v", tlsln.Addr().String())

		w := bytes.NewBuffer([]byte{})
		_, rt, err := client.Request(context.Background(),
			http.MethodGet,
			[]string{"https://" + tlsln.Addr().String()},
			"/v1/test", nil, w)

		assert.EqualError(t, err, "not_found: /v1/test")
		assert.Equal(t, 404, rt)
	}()

	time.Sleep(3 * time.Second)
	tlsln.Close()
	wg.Wait()
}

func TestNewTLSListener_Revoked(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tlsInfo := &TLSInfo{
		CertFile:       serverCertFile,
		KeyFile:        serverKeyFile,
		TrustedCAFile:  serverRootFile,
		CRLVerifier:    verifier{status: ocsp.Revoked},
		ClientAuthType: tls.RequireAndVerifyClientCert,
	}
	defer tlsInfo.Close()

	tlsln, err := NewTLSListener(ln, tlsInfo)
	require.NoError(t, err)

	fmt.Printf("listening on %v", tlsln.Addr().String())
	t.Logf("listening on %v", tlsln.Addr().String())

	router := restserver.NewRouter(notFoundHandler)

	srv := &http.Server{
		Handler:   router.Handler(),
		TLSConfig: tlsInfo.Config(),
	}

	clientTLS, err := tlsconfig.NewClientTLSFromFiles(
		serverCertFile,
		serverKeyFile,
		serverRootFile)
	require.NoError(t, err)

	client := retriable.New(retriable.WithTLS(clientTLS)).WithTimeout(1 * time.Second)
	client.Policy.TotalRetryLimit = 0
	require.NotNil(t, client)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(tlsln)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		t.Logf("sending to %v", tlsln.Addr().String())

		w := bytes.NewBuffer([]byte{})
		_, _, err := client.Request(context.Background(),
			http.MethodGet,
			[]string{"https://" + tlsln.Addr().String()},
			"/v1/test", nil, w)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "unexpected EOF")
			t.Logf("error from %v: %s", tlsln.Addr().String(), err.Error())
		}
	}()

	time.Sleep(3 * time.Second)
	tlsln.Close()
	wg.Wait()
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	marshal.WriteJSON(w, r, httperror.NotFound(r.URL.Path))
}

type verifier struct {
	status int
}

// Update the cache
func (v verifier) Update() error {
	return nil
}

// Verify returns OCSP status:
//
//	ocsp.Revoked - the certificate found in CRL
//	ocsp.Good - the certificate not found in a valid CRL
//	ocsp.Unknown - no CRL or OCSP response found for the certificate
func (v verifier) Verify(crt *x509.Certificate, issuer *x509.Certificate) (int, error) {
	return v.status, nil
}
