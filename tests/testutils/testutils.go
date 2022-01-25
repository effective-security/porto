package testutils

import (
	"fmt"
	"math/rand"
	"os"
	"sync/atomic"
)

var (
	nextPort = int32(os.Getpid()%10000) + int32(17891) + rand.Int31n(1000)
)

// CreateURL returns URL with a random port
func CreateURL(scheme, host string) string {
	next := atomic.AddInt32(&nextPort, 1)
	return fmt.Sprintf("%s://%s:%d", scheme, host, next)
}

// CreateBindAddr returns a bind address with a random port
func CreateBindAddr(host string) string {
	next := atomic.AddInt32(&nextPort, 1)
	return fmt.Sprintf("%s:%d", host, next)
}
