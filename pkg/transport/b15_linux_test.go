package transport

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The keepalive listener sets every TCP keepalive socket option,
// even when the inner listener leaves keepalive disabled.
func TestKeepAliveListenerSocketOptions(t *testing.T) {
	t.Parallel()

	lc := net.ListenConfig{KeepAlive: -1}
	raw, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln, err := NewKeepAliveListener(raw, "http", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	client, err := net.DialTimeout("tcp", raw.Addr().String(), b15Timeout)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	conn, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	rc, err := tcp.SyscallConn()
	require.NoError(t, err)

	opts := map[string]int{}
	var sockErr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		for name, opt := range map[string][2]int{
			"SO_KEEPALIVE":  {syscall.SOL_SOCKET, syscall.SO_KEEPALIVE},
			"TCP_KEEPIDLE":  {syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE},
			"TCP_KEEPINTVL": {syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL},
			"TCP_KEEPCNT":   {syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT},
		} {
			v, err := syscall.GetsockoptInt(int(fd), opt[0], opt[1])
			if err != nil {
				sockErr = err
				return
			}
			opts[name] = v
		}
	}))
	require.NoError(t, sockErr)
	assert.Equal(t, map[string]int{
		"SO_KEEPALIVE":  1,
		"TCP_KEEPIDLE":  30,
		"TCP_KEEPINTVL": 15,
		"TCP_KEEPCNT":   9,
	}, opts)
}
