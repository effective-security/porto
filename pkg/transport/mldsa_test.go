package transport

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handshakeOverPipe runs a handshake against serverCfg from a client that
// trusts rootFile and returns the client's connection state.
func handshakeOverPipe(t *testing.T, serverCfg *tls.Config, rootFile string, clientMaxVersion uint16) (tls.ConnectionState, error) {
	t.Helper()
	rootPEM, err := os.ReadFile(rootFile)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(rootPEM))

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	server := tls.Server(serverConn, serverCfg)
	client := tls.Client(clientConn, &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MaxVersion: clientMaxVersion,
	})
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()
	err = client.Handshake()
	serverErr := <-serverDone
	if err == nil {
		err = serverErr
	}
	return client.ConnectionState(), err
}

// The default minimum version serves an ML-DSA certificate through the
// reloader callback on TLS 1.3.
func TestServerTLSWithReloaderMLDSA(t *testing.T) {
	t.Parallel()

	info := &TLSInfo{
		CertFile:      mldsaCertFile,
		KeyFile:       mldsaKeyFile,
		TrustedCAFile: mldsaRootFile,
	}
	t.Cleanup(info.Close)
	cfg, err := info.ServerTLSWithReloader()
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	require.Empty(t, cfg.Certificates, "served through GetCertificate")

	state, err := handshakeOverPipe(t, cfg, mldsaRootFile, 0)
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), state.Version)
	require.NotEmpty(t, state.PeerCertificates)
	assert.Equal(t, x509.MLDSA, state.PeerCertificates[0].PublicKeyAlgorithm)

	// a TLS 1.2 client is refused by version, not by an internal error
	_, err = handshakeOverPipe(t, cfg, mldsaRootFile, tls.VersionTLS12)
	require.Error(t, err)
	assert.ErrorContains(t, err, "protocol version not supported")
}

func TestServerTLSWithReloaderMinVersion(t *testing.T) {
	t.Parallel()

	tcases := []struct {
		name       string
		certFile   string
		keyFile    string
		rootFile   string
		minVersion uint16
		cipher     []string
		want       uint16
		err        string
	}{
		{
			name:     "default classical",
			certFile: serverCertFile,
			keyFile:  serverKeyFile,
			rootFile: serverRootFile,
			want:     tls.VersionTLS13,
		},
		{
			name:       "TLS 1.2 classical",
			certFile:   serverCertFile,
			keyFile:    serverKeyFile,
			rootFile:   serverRootFile,
			minVersion: tls.VersionTLS12,
			cipher:     []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
			want:       tls.VersionTLS12,
		},
		{
			name:       "TLS 1.3 with ignored cipher suites",
			certFile:   serverCertFile,
			keyFile:    serverKeyFile,
			rootFile:   serverRootFile,
			minVersion: tls.VersionTLS13,
			cipher:     []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
			want:       tls.VersionTLS13,
		},
		{
			name:       "TLS 1.2 ML-DSA",
			certFile:   mldsaCertFile,
			keyFile:    mldsaKeyFile,
			rootFile:   mldsaRootFile,
			minVersion: tls.VersionTLS12,
			err:        "tls: ML-DSA certificates require TLS 1.3 as the minimum version",
		},
		{
			name:       "TLS 1.1",
			certFile:   serverCertFile,
			keyFile:    serverKeyFile,
			rootFile:   serverRootFile,
			minVersion: tls.VersionTLS11,
			err:        "unsupported TLS minimum version 0x0302: use TLS 1.2 or 1.3",
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			info := &TLSInfo{
				CertFile:      tc.certFile,
				KeyFile:       tc.keyFile,
				TrustedCAFile: tc.rootFile,
				MinVersion:    tc.minVersion,
				CipherSuites:  tc.cipher,
			}
			t.Cleanup(info.Close)
			cfg, err := info.ServerTLSWithReloader()
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				assert.Nil(t, cfg)
				assert.Nil(t, info.Config(), "a failed build caches nothing")
				assert.Nil(t, info.tlsReloader)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.MinVersion)

			// the lowest version the server accepts is negotiated by a client
			// capped at it
			state, err := handshakeOverPipe(t, cfg, tc.rootFile, tc.want)
			require.NoError(t, err)
			assert.Equal(t, tc.want, state.Version)
			if tc.want == tls.VersionTLS12 {
				assert.Contains(t, []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				}, state.CipherSuite, "the configured suites restrict TLS 1.2")
			}
		})
	}
}
