package tlsconfig_test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mldsaFiles writes an ML-DSA root, a server chain and a client pair of the
// given parameter set and returns their file names.
func mldsaFiles(t *testing.T, params mldsa.Parameters) (rootFile, serverCert, serverKey, clientCert, clientKey string) {
	t.Helper()
	root := testca.NewEntity(
		testca.Authority,
		testca.MLDSAKey(params),
		testca.Subject(pkix.Name{CommonName: "[TEST] ML-DSA Root"}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	server := root.Issue(
		testca.MLDSAKey(params),
		testca.Subject(pkix.Name{CommonName: "localhost"}),
		testca.ExtKeyUsage(x509.ExtKeyUsageServerAuth),
		testca.DNSName("localhost"),
	)
	client := root.Issue(
		testca.MLDSAKey(params),
		testca.Subject(pkix.Name{CommonName: "mldsa-client"}),
		testca.ExtKeyUsage(x509.ExtKeyUsageClientAuth),
	)
	dir := t.TempDir()
	rootFile = filepath.Join(dir, "root.pem")
	serverCert = filepath.Join(dir, "server.pem")
	serverKey = filepath.Join(dir, "server-key.pem")
	clientCert = filepath.Join(dir, "client.pem")
	clientKey = filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(rootFile, testca.ToPEM(root.Certificate), 0600))
	require.NoError(t, server.SaveCertAndKey(serverCert, serverKey, true))
	require.NoError(t, client.SaveCertAndKey(clientCert, clientKey, true))
	return rootFile, serverCert, serverKey, clientCert, clientKey
}

// handshake runs a TLS handshake over an in-memory pipe and returns both
// connection states; the server error is returned with the client's.
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) (server, client tls.ConnectionState, err error) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	srv := tls.Server(serverConn, serverCfg)
	cli := tls.Client(clientConn, clientCfg)
	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.Handshake() }()
	clientErr := cli.Handshake()
	serverErr := <-serverDone
	if clientErr != nil {
		return srv.ConnectionState(), cli.ConnectionState(), clientErr
	}
	return srv.ConnectionState(), cli.ConnectionState(), serverErr
}

// An ML-DSA server and client authenticate each other over the configs the
// constructors build, on TLS 1.3, for every parameter set.
func TestMLDSAMutualTLS(t *testing.T) {
	t.Parallel()

	tcases := []struct {
		name   string
		params mldsa.Parameters
	}{
		{name: "ML-DSA-44", params: mldsa.MLDSA44()},
		{name: "ML-DSA-65", params: mldsa.MLDSA65()},
		{name: "ML-DSA-87", params: mldsa.MLDSA87()},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rootFile, serverCert, serverKey, clientCert, clientKey := mldsaFiles(t, tc.params)

			serverCfg, err := tlsconfig.NewServerTLSFromFiles(serverCert, serverKey, rootFile, "", tls.RequireAndVerifyClientCert)
			require.NoError(t, err)
			assert.Equal(t, uint16(tls.VersionTLS13), serverCfg.MinVersion)
			require.Len(t, serverCfg.Certificates, 1)
			assert.True(t, tlsconfig.IsMLDSACertificate(&serverCfg.Certificates[0]))

			clientCfg, err := tlsconfig.NewClientTLSFromFiles(clientCert, clientKey, rootFile)
			require.NoError(t, err)
			clientCfg.ServerName = "localhost"

			server, client, err := handshake(t, serverCfg, clientCfg)
			require.NoError(t, err)
			assert.Equal(t, uint16(tls.VersionTLS13), client.Version)
			require.NotEmpty(t, client.PeerCertificates)
			assert.Equal(t, x509.MLDSA, client.PeerCertificates[0].PublicKeyAlgorithm)
			require.NotEmpty(t, server.PeerCertificates)
			assert.Equal(t, x509.MLDSA, server.PeerCertificates[0].PublicKeyAlgorithm)
			assert.Equal(t, "mldsa-client", server.PeerCertificates[0].Subject.CommonName)
		})
	}
}

// A TLS 1.2-only client is refused by the default config and admitted after
// SetMinVersion lowers a classical server to TLS 1.2.
func TestSetMinVersionAdmitsTLS12Clients(t *testing.T) {
	t.Parallel()

	cert, key, err := testca.MakeSelfCertECDSAPem(1)
	require.NoError(t, err)
	certFile, keyFile := writeFiles(t, cert, key)
	serverCfg, err := tlsconfig.NewServerTLSFromFiles(certFile, keyFile, "", "", tls.NoClientCert)
	require.NoError(t, err)

	clientCfg := &tls.Config{
		InsecureSkipVerify: true, // self-signed test certificate
		MaxVersion:         tls.VersionTLS12,
	}
	_, _, err = handshake(t, serverCfg, clientCfg)
	require.Error(t, err, "TLS 1.3 is the default minimum")

	require.NoError(t, tlsconfig.SetMinVersion(serverCfg, tls.VersionTLS12))
	assert.Equal(t, uint16(tls.VersionTLS12), serverCfg.MinVersion)
	_, client, err := handshake(t, serverCfg, clientCfg)
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), client.Version)
}

func TestSetMinVersion(t *testing.T) {
	t.Parallel()

	ecCert, ecKey, err := testca.MakeSelfCertECDSAPem(1)
	require.NoError(t, err)
	ecPair, err := tlsconfig.X509KeyPair(ecCert, ecKey)
	require.NoError(t, err)
	_, mldsaCert, mldsaKey, _, _ := mldsaFiles(t, mldsa.MLDSA44())
	mldsaPair, err := tlsconfig.LoadX509KeyPairWithOCSP(mldsaCert, mldsaKey)
	require.NoError(t, err)

	tcases := []struct {
		name    string
		certs   []tls.Certificate
		version uint16
		want    uint16
		err     string
	}{
		{name: "zero is the default", version: 0, want: tls.VersionTLS13},
		{name: "TLS 1.3", certs: []tls.Certificate{*mldsaPair}, version: tls.VersionTLS13, want: tls.VersionTLS13},
		{name: "TLS 1.2 classical", certs: []tls.Certificate{*ecPair}, version: tls.VersionTLS12, want: tls.VersionTLS12},
		{name: "TLS 1.2 no certificates", version: tls.VersionTLS12, want: tls.VersionTLS12},
		{name: "TLS 1.2 ML-DSA", certs: []tls.Certificate{*ecPair, *mldsaPair}, version: tls.VersionTLS12, err: "tls: ML-DSA certificates require TLS 1.3 as the minimum version"},
		{name: "TLS 1.1", certs: []tls.Certificate{*ecPair}, version: tls.VersionTLS11, err: "unsupported TLS minimum version 0x0302: use TLS 1.2 or 1.3"},
		{name: "unknown", version: 0x0305, err: "unsupported TLS minimum version 0x0305: use TLS 1.2 or 1.3"},
	}
	for _, version := range []uint16{0, tls.VersionTLS12, tls.VersionTLS13} {
		assert.EqualError(t, tlsconfig.SetMinVersion(nil, version), "tls: config is nil")
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const unchanged = uint16(0x0a0a)
			cfg := &tls.Config{MinVersion: unchanged, Certificates: tc.certs}
			err := tlsconfig.SetMinVersion(cfg, tc.version)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Equal(t, unchanged, cfg.MinVersion, "left unchanged")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.MinVersion)
		})
	}
}

func TestIsMLDSACertificate(t *testing.T) {
	t.Parallel()

	ecCert, ecKey, err := testca.MakeSelfCertECDSAPem(1)
	require.NoError(t, err)
	ecPair, err := tlsconfig.X509KeyPair(ecCert, ecKey)
	require.NoError(t, err)
	_, mldsaCert, mldsaKey, _, _ := mldsaFiles(t, mldsa.MLDSA65())
	mldsaPair, err := tlsconfig.LoadX509KeyPairWithOCSP(mldsaCert, mldsaKey)
	require.NoError(t, err)
	require.NotNil(t, mldsaPair.Leaf)

	assert.False(t, tlsconfig.IsMLDSACertificate(nil))
	assert.False(t, tlsconfig.IsMLDSACertificate(&tls.Certificate{}))
	assert.False(t, tlsconfig.IsMLDSACertificate(ecPair))
	assert.True(t, tlsconfig.IsMLDSACertificate(mldsaPair))
	// without a parsed leaf the private key decides, as for tls.X509KeyPair
	// pairs built before Go populated Leaf
	assert.True(t, tlsconfig.IsMLDSACertificate(&tls.Certificate{PrivateKey: mldsaPair.PrivateKey}))
	assert.False(t, tlsconfig.IsMLDSACertificate(&tls.Certificate{PrivateKey: ecPair.PrivateKey}))
	// an opaque signer (HSM, KMS) is classified by its public key
	assert.True(t, tlsconfig.IsMLDSACertificate(&tls.Certificate{PrivateKey: opaqueSigner{mldsaPair.PrivateKey.(crypto.Signer)}}))
	assert.False(t, tlsconfig.IsMLDSACertificate(&tls.Certificate{PrivateKey: opaqueSigner{ecPair.PrivateKey.(crypto.Signer)}}))
	assert.False(t, tlsconfig.IsMLDSACertificate(&tls.Certificate{PrivateKey: "not a signer"}))

	// SetMinVersion sees through the wrapper too
	cfg := &tls.Config{Certificates: []tls.Certificate{{PrivateKey: opaqueSigner{mldsaPair.PrivateKey.(crypto.Signer)}}}}
	assert.EqualError(t, tlsconfig.SetMinVersion(cfg, tls.VersionTLS12), "tls: ML-DSA certificates require TLS 1.3 as the minimum version")
}

// opaqueSigner hides the concrete key type, as an HSM or KMS signer does.
type opaqueSigner struct {
	crypto.Signer
}

func TestParseTLSVersion(t *testing.T) {
	t.Parallel()

	tcases := []struct {
		name string
		want uint16
		err  string
	}{
		{name: "", want: tls.VersionTLS13},
		{name: "1.2", want: tls.VersionTLS12},
		{name: "1.3", want: tls.VersionTLS13},
		{name: "TLS1.2", want: tls.VersionTLS12},
		{name: "tls 1.3", want: tls.VersionTLS13},
		{name: "TLS 1.2", want: tls.VersionTLS12},
		{name: "1.1", err: `unsupported TLS version "1.1": use 1.2 or 1.3`},
		{name: "1.0", err: `unsupported TLS version "1.0": use 1.2 or 1.3`},
		{name: "SSLv3", err: `unsupported TLS version "SSLv3": use 1.2 or 1.3`},
		{name: "0x0304", err: `unsupported TLS version "0x0304": use 1.2 or 1.3`},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tlsconfig.ParseTLSVersion(tc.name)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
