package testutils

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/effective-security/x/netutil"
	"github.com/stretchr/testify/assert"
)

// CreateURL returns "<scheme>://<host>:<free port>"; it panics if no free
// port is found.
func CreateURL(scheme, host string) string {
	bind := CreateBindAddr(host)

	return fmt.Sprintf("%s://%s", scheme, bind)
}

// CreateBindAddr returns "<host>:<free port>" using a port that was free at
// the time of the call; it panics if none is found after 5 attempts.
func CreateBindAddr(host string) string {
	port, err := netutil.FindFreePort(host, 5)
	if err != nil {
		panic("unable to find free port: " + err.Error())
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// JSON returns v marshaled as a JSON string, or "" if marshaling fails.
func JSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// CompareJSON asserts that a and b have identical JSON encodings.
func CompareJSON(t *testing.T, a, b any) {
	t.Helper()
	assert.Equal(t, JSON(a), JSON(b))
}
