package appinit

import (
	"runtime/pprof"

	"github.com/cockroachdb/errors"
)

// cpuProfileCloser stops the process CPU profile started by CPUProfiler.
type cpuProfileCloser struct {
	file   string
	closed bool
}

// Close stops CPU profiling; a second call returns an error.
func (c *cpuProfileCloser) Close() error {
	if c.closed {
		return errors.New("already closed")
	}
	c.closed = true
	pprof.StopCPUProfile()
	return nil
}
