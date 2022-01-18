package netutil

import (
	"net"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamedAddress_Network(t *testing.T) {
	a := namedAddress{network: "tcp4", host: "localhost", port: 8080}
	assert.Equal(t, "tcp4", a.Network(), "Network() should return tcp4")
}

func TestNamedAddress_isNetAddr(t *testing.T) {
	// this will fail to compile if namedAddress doesn't implement the net.Addr interface
	var _ net.Addr = &namedAddress{}
}

func TestNamedAddress_String(t *testing.T) {
	st := func(h string, p uint16, expected string) {
		a := namedAddress{network: "tcp", host: h, port: p}
		assert.Equal(t, expected, a.String(), "Unexpected result for String() for %+v", a)
	}
	st("localhost", 8080, "localhost:8080")
	st("ekspand.com", 5001, "ekspand.com:5001")
	st("", 5001, ":5001")
}

func TestNamedAddress_Resolve(t *testing.T) {
	a := namedAddress{network: "tcp", host: "localhost", port: 7070}
	addr, err := a.Resolve()
	require.NoError(t, err, "Error calling resolve %v", a)
	assert.Equal(t, 7070, addr.Port, "Wrong port resolved")
}

func TestNamedAddress_New(t *testing.T) {
	a, err := newNamedAddress("tcp", "localhost", 7070)
	require.NoError(t, err, "Error creating newNamedAddress")
	assert.Equal(t, "tcp", a.Network(), "Unexpected network in namedAddress")
	assert.Equal(t, "localhost:7070", a.String(), "Unexpected outout for String()")

	_, err = newNamedAddress("bob", "", 0)
	assert.Error(t, err)
}

func TestIsAddrInUse(t *testing.T) {
	assert.False(t, IsAddrInUse(errors.Errorf("not")))
}
