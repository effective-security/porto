package appinit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/effective-security/x/guid"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogs(t *testing.T) {
	closer, err := Logs(&LogConfig{LogPretty: true, LogDebug: true}, "tes")
	require.NoError(t, err)
	assert.Nil(t, closer)

	dir := t.TempDir()

	closer, err = Logs(&LogConfig{LogDir: dir, LogStd: true}, "test")
	require.NoError(t, err)
	require.NotNil(t, closer)
	closer.Close()

	closer, err = Logs(&LogConfig{LogDir: dir + "/notfound", LogStd: false}, "test")
	require.NoError(t, err)
	require.NotNil(t, closer)
	closer.Close()

	// the rotating log file must actually receive output
	fileDir := t.TempDir()
	closer, err = Logs(&LogConfig{LogDir: fileDir, LogStd: false}, "filesvc")
	require.NoError(t, err)
	require.NotNil(t, closer)
	logger.KV(xlog.ERROR, "test", "written_to_file")
	require.NoError(t, closer.Close())
	content, err := os.ReadFile(filepath.Join(fileDir, "filesvc.log"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "written_to_file")

	closer, err = Logs(&LogConfig{LogDir: nullDevName}, "test")
	require.NoError(t, err)
	assert.Nil(t, closer)

	closer, err = Logs(&LogConfig{LogJSON: true}, "test")
	require.NoError(t, err)
	assert.Nil(t, closer)

	closer, err = Logs(&LogConfig{LogStackdriver: true}, "test")
	require.NoError(t, err)
	assert.Nil(t, closer)

	closer, err = Logs(&LogConfig{}, "test")
	require.NoError(t, err)
	assert.Nil(t, closer)
}

func TestCPUProfiler(t *testing.T) {
	closer, err := CPUProfiler("")
	require.NoError(t, err)
	assert.Nil(t, closer)

	cpuf := filepath.Join(os.TempDir(), "proto-test", "profiler")
	_ = os.MkdirAll(cpuf, os.ModePerm)
	defer os.Remove(cpuf)

	_, err = CPUProfiler(cpuf)
	assert.Error(t, err)

	closer, err = CPUProfiler(filepath.Join(cpuf, guid.MustCreate()))
	require.NoError(t, err)
	require.NotNil(t, closer)
	closer.Close()
}
