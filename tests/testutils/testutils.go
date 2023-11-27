package testutils

import (
	"fmt"

	"github.com/effective-security/x/netutil"
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
