package transport

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSHandshakeDeadline(t *testing.T) {
	t.Parallel()
	failures := make(chan error, 1)
	info := &TLSInfo{
		CertFile:         serverCertFile,
		KeyFile:          serverKeyFile,
		HandshakeTimeout: 100 * time.Millisecond,
		HandshakeFailure: recordFailure(failures),
	}
	defer info.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener, err := NewTLSListener(ln, info)
	require.NoError(t, err)
	defer listener.Close()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = io.ReadAll(conn)
	require.NoError(t, err, "stalled handshake should be closed by the server")
	select {
	case err := <-failures:
		var ne net.Error
		require.ErrorAs(t, err, &ne)
		assert.True(t, ne.Timeout())
	case <-time.After(2 * time.Second):
		t.Fatal("missing handshake failure callback")
	}
}

func TestTLSHandshakeClearsDeadline(t *testing.T) {
	t.Parallel()
	const timeout = 200 * time.Millisecond
	info := &TLSInfo{
		CertFile:         serverCertFile,
		KeyFile:          serverKeyFile,
		HandshakeTimeout: timeout,
	}
	defer info.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener, err := NewTLSListener(ln, info)
	require.NoError(t, err)
	defer listener.Close()
	clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", serverRootFile)
	require.NoError(t, err)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", ln.Addr().String(), clientTLS)
	require.NoError(t, err)
	defer conn.Close()
	serverConn, err := listener.Accept()
	require.NoError(t, err)
	defer serverConn.Close()
	// Exercise application I/O after the old handshake deadline has elapsed.
	time.Sleep(2 * timeout)
	_, err = serverConn.Write([]byte("ok"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	body := make([]byte, 2)
	_, err = io.ReadFull(conn, body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))
}
