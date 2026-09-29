package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/soheilhy/cmux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const b15Timeout = 5 * time.Second

// newEMFILE returns the error net.TCPListener.Accept reports when the
// process is out of file descriptors; net/http, grpc and cmux retry it.
func newEMFILE() error {
	return &net.OpError{
		Op:  "accept",
		Net: "tcp",
		Err: os.NewSyscallError("accept4", syscall.EMFILE),
	}
}

// flakyListener returns the queued errors from Accept before delegating to
// the wrapped listener.
type flakyListener struct {
	net.Listener
	mu   sync.Mutex
	errs []error
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

// failingListener fails every Accept with acceptErr until it is closed,
// then with closedErr; called is closed by the first Accept call.
type failingListener struct {
	acceptErr  error
	closedErr  error
	closeOnce  sync.Once
	closed     chan struct{}
	calledOnce sync.Once
	called     chan struct{}
}

func newFailingListener(acceptErr, closedErr error) *failingListener {
	return &failingListener{
		acceptErr: acceptErr,
		closedErr: closedErr,
		closed:    make(chan struct{}),
		called:    make(chan struct{}),
	}
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.calledOnce.Do(func() { close(l.called) })
	select {
	case <-l.closed:
		return nil, l.closedErr
	default:
		return nil, l.acceptErr
	}
}

func (l *failingListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

// connListener returns conn from the first Accept, then blocks until closed.
type connListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newConnListener(conn net.Conn) *connListener {
	l := &connListener{
		conns:  make(chan net.Conn, 1),
		closed: make(chan struct{}),
	}
	l.conns <- conn
	return l
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

// keepAliveRecorder is a connection that records the keepalive config set on it.
type keepAliveRecorder struct {
	net.Conn
	mu      sync.Mutex
	configs []net.KeepAliveConfig
	err     error
}

func (c *keepAliveRecorder) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.configs = append(c.configs, config)
	return c.err
}

func (c *keepAliveRecorder) recorded() []net.KeepAliveConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.configs
}

// serveOK serves 200 OK on ln with net/http until the test ends. tlsCfg is
// the listener's config (nil for plain HTTP); net/http needs it to serve
// HTTP/2 negotiated by ALPN.
func serveOK(t *testing.T, ln net.Listener, tlsCfg *tls.Config) {
	t.Helper()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: b15Timeout,
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(b15Timeout):
			t.Error("server did not stop")
		}
	})
}

// acceptWithin returns the result of ln.Accept, failing the test if it
// does not return within b15Timeout.
func acceptWithin(t *testing.T, ln net.Listener) (net.Conn, error) {
	t.Helper()
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		done <- result{conn: conn, err: err}
	}()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-time.After(b15Timeout):
		t.Fatal("Accept did not return")
		return nil, nil
	}
}

// recordFailure returns a HandshakeFailure callback that keeps the first
// error in failures and drops later ones, so a handshake never blocks on it.
func recordFailure(failures chan error) func(*tls.Conn, error) {
	return func(_ *tls.Conn, err error) {
		select {
		case failures <- err:
		default:
		}
	}
}

func getStatus(t *testing.T, client *http.Client, url string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), b15Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	return res.StatusCode
}

func trustedClient(t *testing.T) *http.Client {
	t.Helper()
	clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", serverRootFile)
	require.NoError(t, err)
	return &http.Client{
		Timeout: b15Timeout,
		Transport: &http.Transport{
			TLSClientConfig: clientTLS,
			// clientTLS offers h2 by ALPN.
			ForceAttemptHTTP2: true,
		},
	}
}

// A failed first call must not leave a config behind.
func TestServerTLSWithReloaderFailureCachesNothing(t *testing.T) {
	t.Parallel()

	info := &TLSInfo{
		CertFile:     serverCertFile,
		KeyFile:      serverKeyFile,
		CipherSuites: []string{"TLS_NOT_A_SUITE"},
	}
	t.Cleanup(info.Close)

	for range 2 {
		cfg, err := info.ServerTLSWithReloader()
		require.EqualError(t, err, `unexpected TLS cipher suite "TLS_NOT_A_SUITE"`)
		assert.Nil(t, cfg)
		assert.Nil(t, info.Config())
		assert.Nil(t, info.tlsReloader)
	}

	// NewTLSListener fails the same way and leaves the listener to the caller.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	_, err = NewTLSListener(ln, info)
	require.EqualError(t, err, `unexpected TLS cipher suite "TLS_NOT_A_SUITE"`)
	assert.Nil(t, info.Config())

	// After the configuration is fixed, a retry builds the complete config.
	// net/http requires an AES-128-GCM suite for HTTP/2.
	info.CipherSuites = []string{
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}
	cfg, err := info.ServerTLSWithReloader()
	require.NoError(t, err)
	assert.Same(t, cfg, info.Config())
	assert.NotNil(t, cfg.GetCertificate)
	assert.Empty(t, cfg.Certificates)
	assert.Equal(t, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}, cfg.CipherSuites)
	assert.NotNil(t, info.tlsReloader)

	tlsln, err := NewTLSListener(ln, info)
	require.NoError(t, err)
	serveOK(t, tlsln, cfg)
	assert.Equal(t, http.StatusOK, getStatus(t, trustedClient(t), "https://"+ln.Addr().String()))
}

// An expired certificate is rejected on every call, not only the first.
func TestServerTLSWithReloaderExpiredCertificate(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ca := testca.NewEntity(
		testca.Authority,
		testca.Subject(pkix.Name{CommonName: "[TEST] B15 Root CA"}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	expired := ca.Issue(
		testca.Subject(pkix.Name{CommonName: "localhost"}),
		testca.ExtKeyUsage(x509.ExtKeyUsageServerAuth),
		testca.DNSName("localhost"),
		testca.NotBefore(now.Add(-48*time.Hour)),
		testca.NotAfter(now.Add(-time.Hour)),
	)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "expired.pem")
	keyFile := filepath.Join(dir, "expired-key.pem")
	require.NoError(t, os.WriteFile(keyFile, testca.PrivKeyToPEM(expired.PrivateKey), 0o600))
	fcert, err := os.Create(certFile)
	require.NoError(t, err)
	require.NoError(t, certutil.EncodeToPEM(fcert, true, expired.Certificate))
	require.NoError(t, fcert.Close())

	info := &TLSInfo{
		CertFile: certFile,
		KeyFile:  keyFile,
	}
	t.Cleanup(info.Close)

	for range 2 {
		cfg, err := info.ServerTLSWithReloader()
		require.EqualError(t, err, "tls: certificate has expired")
		assert.Nil(t, cfg)
		assert.Nil(t, info.Config())
		assert.Nil(t, info.tlsReloader)
	}
}

// Keepalive listeners return Accept errors unchanged.
func TestKeepAliveListenerReturnsAcceptErrorUnchanged(t *testing.T) {
	t.Parallel()

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			acceptErr := newEMFILE()
			inner := newFailingListener(acceptErr, net.ErrClosed)
			ln, err := NewKeepAliveListener(inner, scheme, tlsCfg)
			require.NoError(t, err)

			conn, err := ln.Accept()
			assert.Nil(t, conn)
			assert.Same(t, acceptErr, err)
		})
	}
}

// net/http and cmux keep serving after a temporary Accept error of a
// keepalive listener; with the error wrapped both stopped serving.
func TestKeepAliveListenerServesAfterTemporaryError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		serve func(t *testing.T, ln net.Listener)
	}{
		{
			name: "net/http",
			serve: func(t *testing.T, ln net.Listener) {
				serveOK(t, ln, nil)
			},
		},
		{
			name: "cmux",
			serve: func(t *testing.T, ln net.Listener) {
				m := cmux.New(ln)
				serveOK(t, m.Match(cmux.HTTP1()), nil)
				done := make(chan error, 1)
				go func() { done <- m.Serve() }()
				t.Cleanup(func() {
					_ = ln.Close()
					select {
					case <-done:
					case <-time.After(b15Timeout):
						t.Error("cmux did not stop")
					}
				})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			flaky := &flakyListener{Listener: raw, errs: []error{newEMFILE()}}
			ln, err := NewKeepAliveListener(flaky, "http", nil)
			require.NoError(t, err)

			tc.serve(t, ln)
			client := &http.Client{Timeout: b15Timeout}
			assert.Equal(t, http.StatusOK, getStatus(t, client, "http://"+raw.Addr().String()))
		})
	}
}

// Keepalive listeners set the full keepalive config, and connections
// without keepalive support are returned instead of panicking.
func TestKeepAliveListenerConfig(t *testing.T) {
	t.Parallel()

	want := net.KeepAliveConfig{
		Enable:   true,
		Idle:     30 * time.Second,
		Interval: 15 * time.Second,
		Count:    9,
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()

			server, client := net.Pipe()
			t.Cleanup(func() {
				_ = server.Close()
				_ = client.Close()
			})
			for _, setErr := range []error{nil, errors.New("setsockopt: connection reset by peer")} {
				rec := &keepAliveRecorder{Conn: server, err: setErr}
				ln, err := NewKeepAliveListener(newConnListener(rec), scheme, tlsCfg)
				require.NoError(t, err)

				conn, err := ln.Accept()
				require.NoError(t, err, "a keepalive failure must not fail Accept")
				assert.Equal(t, []net.KeepAliveConfig{want}, rec.recorded())
				if scheme == "https" {
					require.IsType(t, &tls.Conn{}, conn)
					assert.Same(t, rec, conn.(*tls.Conn).NetConn())
				} else {
					assert.Same(t, rec, conn)
				}
				require.NoError(t, ln.Close())
			}

			// net.Pipe connections have no keepalive: returned as is.
			ln, err := NewKeepAliveListener(newConnListener(server), scheme, tlsCfg)
			require.NoError(t, err)
			conn, err := ln.Accept()
			require.NoError(t, err)
			if scheme == "https" {
				require.IsType(t, &tls.Conn{}, conn)
				assert.Same(t, server, conn.(*tls.Conn).NetConn())
			} else {
				assert.Same(t, server, conn)
			}
			require.NoError(t, ln.Close())
		})
	}
}

// The TLS listener passes a temporary Accept error to its caller and
// keeps accepting; previously the accept loop stopped for good.
func TestTLSListenerReturnsAcceptErrorAndContinues(t *testing.T) {
	t.Parallel()

	info := &TLSInfo{
		CertFile: serverCertFile,
		KeyFile:  serverKeyFile,
	}
	t.Cleanup(info.Close)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	acceptErr := newEMFILE()
	tlsln, err := NewTLSListener(&flakyListener{Listener: raw, errs: []error{acceptErr}}, info)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tlsln.Close() })

	conn, err := acceptWithin(t, tlsln)
	assert.Nil(t, conn)
	assert.Same(t, acceptErr, err)

	clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", serverRootFile)
	require.NoError(t, err)
	dialed := make(chan error, 1)
	go func() {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: b15Timeout}, "tcp", raw.Addr().String(), clientTLS)
		if err == nil {
			_ = c.Close()
		}
		dialed <- err
	}()

	conn, err = acceptWithin(t, tlsln)
	require.NoError(t, err)
	require.IsType(t, &tls.Conn{}, conn)
	assert.True(t, conn.(*tls.Conn).ConnectionState().HandshakeComplete)
	_ = conn.Close()
	require.NoError(t, <-dialed)
}

// net/http serves over the TLS listener after a temporary Accept error.
func TestTLSListenerServesAfterTemporaryError(t *testing.T) {
	t.Parallel()

	info := &TLSInfo{
		CertFile: serverCertFile,
		KeyFile:  serverKeyFile,
	}
	t.Cleanup(info.Close)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	flaky := &flakyListener{Listener: raw, errs: []error{newEMFILE(), newEMFILE()}}
	tlsln, err := NewTLSListener(flaky, info)
	require.NoError(t, err)

	serveOK(t, tlsln, info.Config())
	assert.Equal(t, http.StatusOK, getStatus(t, trustedClient(t), "https://"+raw.Addr().String()))
}

// Close returns while the accept loop is waiting to hand an error to an
// Accept call that never comes, whatever error the closed inner listener
// reports afterwards; Accept then reports net.ErrClosed.
func TestTLSListenerCloseWhileForwardingError(t *testing.T) {
	t.Parallel()

	muxClosed := errors.New("mux: server closed")
	for _, closedErr := range []error{net.ErrClosed, muxClosed} {
		t.Run(closedErr.Error(), func(t *testing.T) {
			t.Parallel()

			info := &TLSInfo{
				CertFile: serverCertFile,
				KeyFile:  serverKeyFile,
			}
			t.Cleanup(info.Close)

			inner := newFailingListener(newEMFILE(), closedErr)
			tlsln, err := NewTLSListener(inner, info)
			require.NoError(t, err)

			// Once the wrapped Accept failed, the accept loop is handing the
			// error over, or about to, and nobody calls Accept.
			select {
			case <-inner.called:
			case <-time.After(b15Timeout):
				t.Fatal("the accept loop did not call Accept")
			}
			closed := make(chan error, 1)
			go func() { closed <- tlsln.Close() }()
			select {
			case err := <-closed:
				require.NoError(t, err)
			case <-time.After(b15Timeout):
				t.Fatal("Close blocked")
			}

			conn, err := tlsln.Accept()
			assert.Nil(t, conn)
			assert.ErrorIs(t, err, net.ErrClosed)
			// A second Close neither panics nor blocks.
			require.NoError(t, tlsln.Close())
		})
	}
}

// The removed TLSInfo policy fields are replaced by VerifyConnection on the
// config returned by ServerTLSWithReloader; NewTLSListener enforces it.
func TestTLSListenerHonorsVerifyConnection(t *testing.T) {
	t.Parallel()

	failures := make(chan error, 1)
	info := &TLSInfo{
		CertFile:         serverCertFile,
		KeyFile:          serverKeyFile,
		HandshakeFailure: recordFailure(failures),
	}
	t.Cleanup(info.Close)

	errRejected := errors.New("client rejected by policy")
	cfg, err := info.ServerTLSWithReloader()
	require.NoError(t, err)
	cfg.VerifyConnection = func(tls.ConnectionState) error { return errRejected }

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tlsln, err := NewTLSListener(raw, info)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tlsln.Close() })

	clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", serverRootFile)
	require.NoError(t, err)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: b15Timeout}, "tcp", raw.Addr().String(), clientTLS)
	if err == nil {
		// TLS 1.3 clients finish before the server verifies; the first read fails.
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(b15Timeout)))
		_, err = conn.Read(make([]byte, 1))
		_ = conn.Close()
	}
	require.Error(t, err)

	select {
	case herr := <-failures:
		assert.ErrorIs(t, herr, errRejected)
	case <-time.After(b15Timeout):
		t.Fatal("missing handshake failure callback")
	}
}
