package netutil_test

import (
	"testing"

	"github.com/effective-security/porto/x/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FindFreePort(t *testing.T) {
	p, err := netutil.FindFreePort("", 0)
	require.NoError(t, err)
	assert.NotEmpty(t, p)
}
