package netutil

import (
	"net"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/x", "netutil")

// FindFreePort returns a free port found on a host
func FindFreePort(host string, maxAttempts int) (int, error) {
	if host == "" {
		host = "localhost"
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for i := 0; i < maxAttempts; i++ {
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			logger.KV(xlog.ERROR,
				"reason", "unable to resolve tcp addr",
				"err", err.Error())
			continue
		}
		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			l.Close()
			logger.KV(xlog.ERROR,
				"reason", "unable to listen",
				"addr", addr,
				"err", err.Error())
			continue
		}

		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		return port, nil
	}

	return 0, errors.Errorf("no free port found")
}
