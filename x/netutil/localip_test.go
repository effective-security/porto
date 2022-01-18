package netutil_test

import (
	"testing"
	"time"

	"github.com/effective-security/porto/x/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LocalIP(t *testing.T) {
	ip, err := netutil.GetLocalIP()
	require.NoError(t, err, "failed to resolve local IP address")
	assert.NotEmpty(t, ip)

	_, err = netutil.IsPrivateAddress(ip)
	require.NoError(t, err)
}

func TestIsPrivateAddr(t *testing.T) {
	testData := map[string]bool{
		"127.0.0.0":   true,
		"10.0.0.0":    true,
		"169.254.0.0": true,
		"192.168.0.0": true,
		"::1":         true,
		"fc00::":      true,

		"172.15.0.0": false,
		"172.16.0.0": true,
		"172.31.0.0": true,
		"172.32.0.0": false,

		"147.12.56.11": false,
	}

	for addr, isLocal := range testData {
		isPrivate, err := netutil.IsPrivateAddress(addr)
		require.NoError(t, err)
		assert.Equal(t, isLocal, isPrivate, addr)
	}
}

func Test_WaitForNetwork(t *testing.T) {
	ip, err := netutil.WaitForNetwork(0)
	require.NoError(t, err)
	assert.NotEmpty(t, ip)

	ip, err = netutil.WaitForNetwork(time.Second)
	require.NoError(t, err)
	assert.NotEmpty(t, ip)
}
