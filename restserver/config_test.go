package restserver_test

import (
	"os"
	"testing"

	rest "github.com/effective-security/porto/restserver"
	"github.com/stretchr/testify/assert"
)

func Test_GetPortAndHost(t *testing.T) {
	hostname, _ := os.Hostname()

	bindAddr := ""
	assert.Equal(t, "443", rest.GetPort(bindAddr))
	assert.Equal(t, hostname, rest.GetHostName(bindAddr))

	bindAddr = "localhost"
	assert.Equal(t, "443", rest.GetPort(bindAddr))
	assert.Equal(t, "localhost", rest.GetHostName(bindAddr))

	bindAddr = ":7865"
	assert.Equal(t, "7865", rest.GetPort(bindAddr))
	assert.Equal(t, hostname, rest.GetHostName(bindAddr))

	bindAddr = "http://hostname:7865"
	assert.Equal(t, "7865", rest.GetPort(bindAddr))
	assert.Equal(t, "http://hostname", rest.GetHostName(bindAddr))

	bindAddr = "hostname:7865"
	assert.Equal(t, "7865", rest.GetPort(bindAddr))
	assert.Equal(t, "hostname", rest.GetHostName(bindAddr))
}
