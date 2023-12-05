package testutils

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/effective-security/x/netutil"
	"github.com/stretchr/testify/assert"
)

// CreateURL returns URL with a random port
func CreateURL(scheme, host string) string {
	bind := CreateBindAddr(host)

	return fmt.Sprintf("%s://%s", scheme, bind)
}

// CreateBindAddr returns a bind address with a random port
func CreateBindAddr(host string) string {
	port, err := netutil.FindFreePort(host, 5)
	if err != nil {
		panic("unable to find free port: " + err.Error())
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// JSON returns json string
func JSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// CompareJSON asserts that JSON encodings are the same
func CompareJSON(t *testing.T, a, b any) {
	t.Helper()
	assert.Equal(t, JSON(a), JSON(b))
}
