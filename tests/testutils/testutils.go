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

// CreateURLs returns URL with a random port
func CreateURLs(scheme, host string) string {
	next := atomic.AddInt32(&nextPort, 1)
	return fmt.Sprintf("%s://%s:%d", scheme, host, next)
}
