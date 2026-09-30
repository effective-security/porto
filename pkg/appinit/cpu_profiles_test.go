package appinit

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/pprof"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CPU profiling is process-global, so these tests must not run in parallel.

// skipIfTestCPUProfile skips when `go test -cpuprofile` runs the process CPU
// profile.
func skipIfTestCPUProfile(t *testing.T) {
	t.Helper()
	if f := flag.Lookup("test.cpuprofile"); f != nil && f.Value.String() != "" {
		t.Skip("go test -cpuprofile runs the process CPU profile")
	}
}

func TestCPUProfilerLifecycle(t *testing.T) {
	skipIfTestCPUProfile(t)
	file := filepath.Join(t.TempDir(), "cpu.prof")
	closer, err := CPUProfiler(file)
	require.NoError(t, err)
	require.NotNil(t, closer)
	t.Cleanup(func() { _ = closer.Close() })
	pc, ok := closer.(*cpuProfileCloser)
	require.True(t, ok)

	// A second call fails before it creates, and so truncates, the file.
	second, err := CPUProfiler(file)
	require.EqualError(t, err, "CPU profile already running")
	assert.Nil(t, second)

	require.NoError(t, closer.Close())
	assert.ErrorIs(t, pc.file.Close(), os.ErrClosed, "Close closes the profile file")
	assert.EqualError(t, closer.Close(), "CPU profile already closed")

	// The profile is complete: its gzip stream ends with a valid trailer.
	f, err := os.Open(file)
	require.NoError(t, err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	_, err = io.ReadAll(gz)
	require.NoError(t, err)

	// The profile slot is free again.
	third, err := CPUProfiler(filepath.Join(t.TempDir(), "third.prof"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = third.Close() })
	require.NoError(t, third.Close())
}

// A profile started outside CPUProfiler is detected by pprof.
func TestCPUProfilerForeignProfile(t *testing.T) {
	skipIfTestCPUProfile(t)
	running, err := os.Create(filepath.Join(t.TempDir(), "running.prof"))
	require.NoError(t, err)
	require.NoError(t, pprof.StartCPUProfile(running))
	t.Cleanup(func() {
		pprof.StopCPUProfile()
		_ = running.Close()
	})

	f, err := os.Create(filepath.Join(t.TempDir(), "second.prof"))
	require.NoError(t, err)
	pc, err := startCPUProfile(f)
	require.ErrorContains(t, err, "unable to start CPU profile "+f.Name())
	assert.Nil(t, pc)
	assert.ErrorIs(t, f.Close(), os.ErrClosed, "a failed start closes the file")

	file := filepath.Join(t.TempDir(), "third.prof")
	closer, err := CPUProfiler(file)
	require.ErrorContains(t, err, "unable to start CPU profile "+file)
	assert.Nil(t, closer)
	_, err = os.Stat(file)
	assert.ErrorIs(t, err, fs.ErrNotExist, "a failed start removes the file")
	assert.False(t, cpuProfileRunning.Load())
}

// A failed start keeps the profile slot until its file is removed, so a call
// that starts once the foreign profile stops cannot lose its file to that
// removal (P-089).
func TestCPUProfilerFailedStartHoldsSlot(t *testing.T) {
	skipIfTestCPUProfile(t)
	require.NoError(t, pprof.StartCPUProfile(io.Discard))
	t.Cleanup(pprof.StopCPUProfile)

	file := filepath.Join(t.TempDir(), "cpu.prof")
	var retry io.Closer
	var retryErr error
	removeCPUProfile = func(name string) error {
		pprof.StopCPUProfile()
		retry, retryErr = CPUProfiler(file)
		return os.Remove(name)
	}
	t.Cleanup(func() {
		removeCPUProfile = os.Remove
		if retry != nil {
			_ = retry.Close()
		}
	})

	closer, err := CPUProfiler(file)
	require.ErrorContains(t, err, "unable to start CPU profile "+file)
	assert.Nil(t, closer)
	require.EqualError(t, retryErr, "CPU profile already running")
	assert.Nil(t, retry)
	_, err = os.Stat(file)
	assert.ErrorIs(t, err, fs.ErrNotExist, "a failed start removes the file")
	assert.False(t, cpuProfileRunning.Load())

	// Once the removal completed, a call on the same path succeeds.
	removeCPUProfile = os.Remove
	closer, err = CPUProfiler(file)
	require.NoError(t, err)
	t.Cleanup(func() { _ = closer.Close() })
	require.NoError(t, closer.Close())
	_, err = os.Stat(file)
	assert.NoError(t, err)
}

// A failed removal after a failed start is reported with the start error, as
// its secondary error, and still frees the profile slot.
func TestCPUProfilerFailedStartRemoveError(t *testing.T) {
	skipIfTestCPUProfile(t)
	require.NoError(t, pprof.StartCPUProfile(io.Discard))
	t.Cleanup(pprof.StopCPUProfile)

	removeErr := errors.New("remove failed")
	var removed string
	removeCPUProfile = func(name string) error {
		removed = name
		return removeErr
	}
	t.Cleanup(func() {
		removeCPUProfile = os.Remove
		cpuProfileRunning.Store(false)
	})

	file := filepath.Join(t.TempDir(), "cpu.prof")
	closer, err := CPUProfiler(file)
	require.ErrorContains(t, err, "unable to start CPU profile "+file)
	assert.Nil(t, closer)
	assert.Equal(t, file, removed)
	assert.Contains(t, fmt.Sprintf("%+v", err), "unable to remove CPU profile: remove failed")
	assert.False(t, cpuProfileRunning.Load())
}
