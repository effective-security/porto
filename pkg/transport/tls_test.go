package transport

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	serverCertFile string
	serverKeyFile  string
	serverRootFile string
)

func init() {
	ca1 := testca.NewEntity(
		testca.Authority,
		testca.Subject(pkix.Name{
			CommonName: "[TEST] Root CA One",
		}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	inter1 := ca1.Issue(
		testca.Authority,
		testca.Subject(pkix.Name{
			CommonName: "[TEST] Issuing CA One Level 1",
		}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	srv := inter1.Issue(
		testca.Subject(pkix.Name{
			CommonName: "localhost",
		}),
		testca.ExtKeyUsage(x509.ExtKeyUsageServerAuth),
		testca.ExtKeyUsage(x509.ExtKeyUsageClientAuth),
		testca.DNSName("localhost", "127.0.0.1"),
	)

	tmpDir := filepath.Join(os.TempDir(), "test-transport")
	os.MkdirAll(tmpDir, os.ModePerm)

	serverCertFile = filepath.Join(tmpDir, "test-server.pem")
	serverKeyFile = filepath.Join(tmpDir, "test-server-key.pem")
	serverRootFile = filepath.Join(tmpDir, "test-server-rootca.pem")

	//
	// save keys
	//
	fkey, err := os.Create(serverKeyFile)
	if err != nil {
		logger.Panic(err)
	}
	fkey.Write(testca.PrivKeyToPEM(srv.PrivateKey))
	fkey.Close()

	//
	// save server certs
	//
	fcert, err := os.Create(serverCertFile)
	if err != nil {
		logger.Panic(err)
	}
	certutil.EncodeToPEM(fcert, true, srv.Certificate, inter1.Certificate)
	fcert.Close()

	fcert, err = os.Create(serverRootFile)
	if err != nil {
		logger.Panic(err)
	}
	certutil.EncodeToPEM(fcert, true, ca1.Certificate)
	fcert.Close()
}

func TestServerTLSWithReloader(t *testing.T) {
	tlsInfo := &TLSInfo{
		CertFile:      serverCertFile,
		KeyFile:       serverKeyFile,
		TrustedCAFile: serverRootFile,
		CipherSuites:  []string{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
	}
	assert.False(t, tlsInfo.Empty())
	assert.NotEmpty(t, tlsInfo.String())
	assert.Nil(t, tlsInfo.Config())

	defer tlsInfo.Close()
	cfg, err := tlsInfo.ServerTLSWithReloader()
	require.NoError(t, err)
	assert.NotNil(t, tlsInfo.Config())

	cfg2, err := tlsInfo.ServerTLSWithReloader()
	require.NoError(t, err)
	assert.Equal(t, cfg, cfg2)
	tlsInfo.Close()
}

func TestServerTLSWithReloaderWithoutSNI(t *testing.T) {
	t.Parallel()
	info := &TLSInfo{
		CertFile: serverCertFile,
		KeyFile:  serverKeyFile,
	}
	cfg, err := info.ServerTLSWithReloader()
	require.NoError(t, err)
	t.Cleanup(info.Close)
	require.Empty(t, cfg.Certificates)
	require.NotNil(t, cfg.GetCertificate)

	var callbackCalls atomic.Int32
	originalCallback := cfg.GetCertificate
	serverConfig := cfg.Clone()
	serverConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		callbackCalls.Add(1)
		return originalCallback(hello)
	}
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	server := tls.Server(serverConn, serverConfig)
	client := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true}) // test certificate
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()
	require.NoError(t, client.Handshake())
	require.NoError(t, <-serverDone)
	assert.Equal(t, int32(1), callbackCalls.Load())
}
