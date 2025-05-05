package appinit

import (
	"os"
	"path/filepath"
	"runtime/pprof"
	"testing"

	"github.com/effective-security/x/guid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCpuProfileCloser(t *testing.T) {
	output := filepath.Join(os.TempDir(), "porto", guid.MustCreate())
	_ = os.MkdirAll(output, 0777)
	defer os.Remove(output)

	cpuf, err := os.Create(filepath.Join(output, "profiler"))
	require.NoError(t, err)

	_ = pprof.StartCPUProfile(cpuf)
	closer := &cpuProfileCloser{}

	err = closer.Close()
	assert.NoError(t, err)
	err = closer.Close()
	assert.Error(t, err)
}
