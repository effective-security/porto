package tlsconfig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

const (
	pemTypeCertificate = "CERTIFICATE"
	pemTypePrivateKey  = "PRIVATE KEY"
)

// certPEM returns a PEM certificate for pub, signed by signer and valid
// until notAfter.
func certPEM(t *testing.T, pub any, signer crypto.Signer, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "keypair-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
}

// pkcs8PEM returns key as an unencrypted PKCS#8 "PRIVATE KEY" PEM block.
func pkcs8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der})
}

// asX25519Cert returns the Ed25519 certificate edCert with its subject
// public key algorithm changed to X25519 (OID 1.3.101.112 to 1.3.101.110),
// which x509 cannot issue and parses as UnknownPublicKeyAlgorithm with a nil
// PublicKey. The signature no longer verifies; parsing does not check it.
func asX25519Cert(t *testing.T, edCert []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(edCert)
	require.NotNil(t, block)
	crt, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}
	x25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x6e}
	spki := crt.RawSubjectPublicKeyInfo
	require.Equal(t, 1, bytes.Count(spki, ed25519OID))
	x25519SPKI := bytes.Replace(spki, ed25519OID, x25519OID, 1)
	der := bytes.Replace(block.Bytes, spki, x25519SPKI, 1)
	crt, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Equal(t, x509.UnknownPublicKeyAlgorithm, crt.PublicKeyAlgorithm)
	require.Nil(t, crt.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
}

// writeFiles writes cert and key into a new temporary folder.
func writeFiles(t *testing.T, cert, key []byte) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, cert, 0600))
	require.NoError(t, os.WriteFile(keyFile, key, 0600))
	return certFile, keyFile
}

func TestX509KeyPairKeyTypes(t *testing.T) {
	t.Parallel()

	notAfter := time.Now().Add(time.Hour)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherECKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, otherEdKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	rsaCert := certPEM(t, rsaKey.Public(), rsaKey, notAfter)
	ecCert := certPEM(t, ecKey.Public(), ecKey, notAfter)
	edCert := certPEM(t, edKey.Public(), edKey, notAfter)
	x25519Cert := asX25519Cert(t, edCert)

	garbageCert := pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: []byte("not a certificate")})
	garbageKey := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: []byte("not a key")})
	nonsense := pem.EncodeToMemory(&pem.Block{Type: "NONSENSE", Bytes: []byte("foo")})

	tcases := []struct {
		name    string
		cert    []byte
		key     []byte
		wantKey crypto.PrivateKey
		err     string
	}{
		{name: "rsa pkcs8", cert: rsaCert, key: pkcs8PEM(t, rsaKey), wantKey: rsaKey},
		{name: "ecdsa pkcs8", cert: ecCert, key: pkcs8PEM(t, ecKey), wantKey: ecKey},
		{name: "ed25519 pkcs8", cert: edCert, key: pkcs8PEM(t, edKey), wantKey: edKey},
		{name: "rsa other key", cert: rsaCert, key: pkcs8PEM(t, otherRSAKey), err: "tls: private key does not match public key"},
		{name: "ecdsa other key", cert: ecCert, key: pkcs8PEM(t, otherECKey), err: "tls: private key does not match public key"},
		{name: "ed25519 other key", cert: edCert, key: pkcs8PEM(t, otherEdKey), err: "tls: private key does not match public key"},
		{name: "ed25519 cert ecdsa key", cert: edCert, key: pkcs8PEM(t, ecKey), err: "tls: private key type does not match public key type"},
		{name: "x25519 cert", cert: x25519Cert, key: pkcs8PEM(t, edKey), err: "tls: unknown public key algorithm"},
		{name: "x25519 key", cert: rsaCert, key: pkcs8PEM(t, x25519Key), err: "tls: found unknown private key type in PKCS#8 wrapping"},
		{name: "unparsable key", cert: rsaCert, key: garbageKey, err: "tls: failed to parse private key"},
		{name: "unparsable certificate", cert: garbageCert, key: pkcs8PEM(t, rsaKey), err: "x509: malformed certificate"},
		{name: "empty key", cert: rsaCert, key: nil, err: "tls: failed to find any PEM data in key input"},
		{name: "no key block", cert: rsaCert, key: nonsense, err: `tls: failed to find PEM block with type ending in "PRIVATE KEY" in key input after skipping PEM blocks of the following types: [NONSENSE]`},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pair, err := tlsconfig.X509KeyPair(tc.cert, tc.key)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, pair)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pair.Leaf)
			assert.Equal(t, pair.Certificate[0], pair.Leaf.Raw)
			assert.Equal(t, tc.wantKey, pair.PrivateKey)
		})
	}
}

func TestX509KeyPairWithOCSPStaple(t *testing.T) {
	t.Parallel()

	ca := testca.NewEntity(
		testca.Authority,
		testca.Subject(pkix.Name{CommonName: "[TEST] OCSP Root"}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	srv := ca.Issue(
		testca.Subject(pkix.Name{CommonName: "localhost"}),
		testca.ExtKeyUsage(x509.ExtKeyUsageServerAuth),
		testca.DNSName("localhost"),
	)
	leafPEM := testca.ToPEM(srv.Certificate)
	chainPEM := append(append([]byte{}, leafPEM...), testca.ToPEM(ca.Certificate)...)
	keyPEM := testca.PrivKeyToPEM(srv.PrivateKey)

	staple := func(status int, nextUpdate time.Time) []byte {
		res, err := ocsp.CreateResponse(ca.Certificate, ca.Certificate, ocsp.Response{
			Status:       status,
			SerialNumber: srv.Certificate.SerialNumber,
			ThisUpdate:   time.Now().Add(-2 * time.Hour).UTC(),
			NextUpdate:   nextUpdate.UTC(),
			RevokedAt:    time.Now().Add(-2 * time.Hour).UTC(),
		}, ca.PrivateKey)
		require.NoError(t, err)
		return res
	}
	good := staple(ocsp.Good, time.Now().Add(time.Hour))
	badIssuer := append(append([]byte{}, leafPEM...),
		pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: []byte("not a certificate")})...)

	tcases := []struct {
		name   string
		chain  []byte
		staple []byte
		// stapled reports whether the staple is kept
		stapled bool
		err     string
	}{
		{name: "good", chain: chainPEM, staple: good, stapled: true},
		{name: "expired", chain: chainPEM, staple: staple(ocsp.Good, time.Now().Add(-time.Hour))},
		{name: "unparsable", chain: chainPEM, staple: []byte("not an OCSP response")},
		{name: "no issuer in chain", chain: leafPEM, staple: good},
		{name: "revoked", chain: chainPEM, staple: staple(ocsp.Revoked, time.Now().Add(time.Hour)), err: "tls: certificate is revoked"},
		{name: "unparsable issuer", chain: badIssuer, staple: good, err: "failed to parse issuer: x509: malformed certificate"},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pair, err := tlsconfig.X509KeyPairWithOCSP(tc.chain, keyPEM, tc.staple)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, pair)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, srv.Certificate.Raw, pair.Leaf.Raw)
			if tc.stapled {
				assert.Equal(t, tc.staple, pair.OCSPStaple)
			} else {
				assert.Nil(t, pair.OCSPStaple)
			}
		})
	}
}

func TestLoadFromMissingFiles(t *testing.T) {
	t.Parallel()

	cert, key, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	certFile, keyFile := writeFiles(t, cert, key)
	missing := filepath.Join(t.TempDir(), "missing.pem")

	_, err = tlsconfig.LoadX509KeyPairWithOCSP(missing, keyFile)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = tlsconfig.LoadX509KeyPairWithOCSP(certFile, missing)
	assert.ErrorIs(t, err, fs.ErrNotExist)

	_, err = tlsconfig.NewServerTLSFromFiles(missing, keyFile, "", "", tls.NoClientCert)
	assert.ErrorIs(t, err, fs.ErrNotExist)

	_, err = tlsconfig.NewClientTLSFromFiles(certFile, missing, "")
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = tlsconfig.NewClientTLSFromFiles("", "", missing)
	require.ErrorIs(t, err, fs.ErrNotExist)
	// the cause's text after the prefix is the OS error message
	prefix := "unable to read CA file " + missing + ": open " + missing + ": "
	assert.True(t, strings.HasPrefix(err.Error(), prefix), "%q has prefix %q", err.Error(), prefix)
}

func TestNewClientTLSFromFiles(t *testing.T) {
	t.Parallel()

	cert, key, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	certFile, keyFile := writeFiles(t, cert, key)

	cfg, err := tlsconfig.NewClientTLSFromFiles(certFile, keyFile, certFile)
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
	require.Len(t, cfg.Certificates, 1)
	require.NotNil(t, cfg.Certificates[0].Leaf)
	block, _ := pem.Decode(cert)
	require.NotNil(t, block)
	assert.Equal(t, block.Bytes, cfg.Certificates[0].Leaf.Raw)
	require.NotNil(t, cfg.RootCAs)
	_, err = cfg.Certificates[0].Leaf.Verify(x509.VerifyOptions{
		Roots:     cfg.RootCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	assert.NoError(t, err, "the roots file is trusted")

	cfg, err = tlsconfig.NewClientTLSFromFiles("", "", "")
	require.NoError(t, err)
	assert.Empty(t, cfg.Certificates)
	assert.Nil(t, cfg.RootCAs, "the system roots are used")
}

// The reloader rejects an expired certificate that NewClientTLSFromFiles
// accepts, so the reloading constructors fail on it.
func TestReloadingConstructorsRejectInvalidFiles(t *testing.T) {
	t.Parallel()

	expiredCert, expiredKey, err := testca.MakeSelfCertRSAPem(-1)
	require.NoError(t, err)
	expiredCertFile, expiredKeyFile := writeFiles(t, expiredCert, expiredKey)
	validCert, validKey, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	validCertFile, validKeyFile := writeFiles(t, validCert, validKey)
	missing := filepath.Join(t.TempDir(), "missing.pem")

	_, err = tlsconfig.NewClientTLSFromFiles(expiredCertFile, expiredKeyFile, "")
	require.NoError(t, err, "the loader accepts expired certificates")

	// the reloader's first load reports a load count of 0
	const expiredErr = "count: 0: certificate expired"
	cfg, reloader, err := tlsconfig.NewClientTLSWithReloader(expiredCertFile, expiredKeyFile, "", time.Hour)
	assert.EqualError(t, err, expiredErr)
	assert.Nil(t, cfg)
	assert.Nil(t, reloader)

	cfg, reloader, err = tlsconfig.NewClientTLSWithReloader(validCertFile, validKeyFile, missing, time.Hour)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	assert.Nil(t, cfg)
	assert.Nil(t, reloader)

	tr, err := tlsconfig.NewHTTPTransportWithReloader(expiredCertFile, expiredKeyFile, "", time.Hour, nil)
	assert.EqualError(t, err, expiredErr)
	assert.Nil(t, tr)

	tr, err = tlsconfig.NewHTTPTransportWithReloader(validCertFile, validKeyFile, missing, time.Hour, nil)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	assert.Nil(t, tr)
}

func TestHTTPTransportRoundTripAndClose(t *testing.T) {
	t.Parallel()

	cert, key, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	certFile, keyFile := writeFiles(t, cert, key)
	tr, err := tlsconfig.NewHTTPTransportWithReloader(certFile, keyFile, "", time.Hour, nil)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err = tr.RoundTrip(req)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, resp)

	require.NoError(t, tr.Close())
	assert.EqualError(t, tr.Close(), "already closed")
}

func TestKeypairReloaderNil(t *testing.T) {
	t.Parallel()

	var k *tlsconfig.KeypairReloader
	assert.Nil(t, k.Keypair())
	certFile, keyFile := k.CertAndKeyFiles()
	assert.Empty(t, certFile)
	assert.Empty(t, keyFile)
	assert.NoError(t, k.Close())
}

func TestKeypairReloaderCloseTwice(t *testing.T) {
	t.Parallel()

	cert, key, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	certFile, keyFile := writeFiles(t, cert, key)
	k, err := tlsconfig.NewKeypairReloader("", certFile, keyFile, time.Hour)
	require.NoError(t, err)

	require.NoError(t, k.Close())
	assert.EqualError(t, k.Close(), "already closed")
	assert.EqualError(t, k.Reload(), "reloader closed")
}
