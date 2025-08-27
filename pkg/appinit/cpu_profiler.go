package appinit

import (
	"runtime/pprof"

	"github.com/cockroachdb/errors"
)

type cpuProfileCloser struct {
	file   string
	closed bool
}

func (c *cpuProfileCloser) Close() error {
	if c.closed {
		return errors.New("already closed")
	}
	c.closed = true
	pprof.StopCPUProfile()
	return nil
}
