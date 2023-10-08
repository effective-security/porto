package appinit

import (
	"os"
	"path"
	"testing"

	"github.com/effective-security/porto/x/guid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogs(t *testing.T) {
	closer, err := Logs(&LogConfig{LogPretty: true, LogDebug: true}, "tes")
	require.NoError(t, err)
	assert.Nil(t, closer)

	dir := path.Join(os.TempDir(), "proto-test", "logs")
	_ = os.MkdirAll(dir, os.ModePerm)
	defer os.Remove(dir)

	closer, err = Logs(&LogConfig{LogDir: dir, LogStd: true}, "test")
	require.NoError(t, err)
	require.NotNil(t, closer)
	closer.Close()

	closer, err = Logs(&LogConfig{LogDir: nullDevName}, "test")
	require.NoError(t, err)
	assert.Nil(t, closer)
}

func TestCPUProfiler(t *testing.T) {
	closer, err := CPUProfiler("")
	require.NoError(t, err)
	assert.Nil(t, closer)

	cpuf := path.Join(os.TempDir(), "proto-test", "profiler")
	_ = os.MkdirAll(cpuf, os.ModePerm)
	defer os.Remove(cpuf)

	_, err = CPUProfiler(cpuf)
	assert.Error(t, err)

	closer, err = CPUProfiler(path.Join(cpuf, guid.MustCreate()))
	require.NoError(t, err)
	require.NotNil(t, closer)
	closer.Close()
}
