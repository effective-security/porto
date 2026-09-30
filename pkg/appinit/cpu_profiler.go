package appinit

import (
	"os"
	"runtime/pprof"
	"sync/atomic"

	"github.com/cockroachdb/errors"
)

// cpuProfileRunning is held from a CPUProfiler call until its profile stops,
// or until the call fails (after removing any file it created), so a second
// call fails before it truncates any file.
var cpuProfileRunning atomic.Bool

// removeCPUProfile removes the file of a failed start; tests replace it to
// call CPUProfiler while the removal runs.
var removeCPUProfile = os.Remove

// cpuProfileCloser stops the process CPU profile started by CPUProfiler and
// closes its file.
type cpuProfileCloser struct {
	file   *os.File
	closed atomic.Bool
}

// startCPUProfile starts the process CPU profile writing to f. On failure it
// closes f.
func startCPUProfile(f *os.File) (*cpuProfileCloser, error) {
	if err := pprof.StartCPUProfile(f); err != nil {
		return nil, errors.CombineErrors(
			errors.Wrapf(err, "unable to start CPU profile %s", f.Name()),
			errors.WithMessage(f.Close(), "unable to close CPU profile"))
	}
	return &cpuProfileCloser{file: f}, nil
}

// Close stops CPU profiling, which writes the rest of the profile, and closes
// the file; a later call returns an error.
func (c *cpuProfileCloser) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return errors.New("CPU profile already closed")
	}
	pprof.StopCPUProfile()
	err := errors.Wrapf(c.file.Close(), "unable to close CPU profile %s", c.file.Name())
	cpuProfileRunning.Store(false)
	return err
}
