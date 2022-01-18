package netutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NodeInfo(t *testing.T) {
	n, err := NewNodeInfo(nil)
	require.NoError(t, err)
	require.NotNil(t, n)
	assert.NotEmpty(t, n.HostName())
	assert.NotEmpty(t, n.LocalIP())
	assert.Equal(t, n.HostName(), n.NodeName())

	n, err = NewNodeInfo(func(hostname string) string {
		return "nodename"
	})
	require.NoError(t, err)
	require.NotNil(t, n)
	assert.NotEmpty(t, n.HostName())
	assert.NotEmpty(t, n.LocalIP())
	assert.Equal(t, "nodename", n.NodeName())
}
