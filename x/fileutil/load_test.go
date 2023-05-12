package fileutil_test

import (
	"os"
	"path"
	"testing"

	"github.com/effective-security/porto/x/fileutil"
	"github.com/effective-security/porto/x/guid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LoadConfigWithSchema_plain(t *testing.T) {
	c, err := fileutil.LoadConfigWithSchema("test_data")
	require.NoError(t, err)
	assert.Equal(t, "test_data", c)
}

func Test_LoadConfigWithSchema_file(t *testing.T) {
	c, err := fileutil.LoadConfigWithSchema("file://./load.go")
	require.NoError(t, err)
	require.NotEmpty(t, c)
	assert.Contains(t, c, "package fileutil")
}

func Test_SaveConfigWithSchema_file(t *testing.T) {
	tmpDir := path.Join(os.TempDir(), "cfg-test")
	_ = os.MkdirAll(tmpDir, os.ModePerm)
	defer os.RemoveAll(tmpDir)

	cfg := "file://" + path.Join(tmpDir, guid.MustCreate())
	err := fileutil.SaveConfigWithSchema(cfg, "test")
	require.NoError(t, err)

	c, err := fileutil.LoadConfigWithSchema(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test", c)
}

func Test_SaveConfigWithSchema_env(t *testing.T) {
	cfg := "env://" + guid.MustCreate()
	defer os.Setenv(cfg, "")

	err := fileutil.SaveConfigWithSchema(cfg, "test")
	require.NoError(t, err)

	c, err := fileutil.LoadConfigWithSchema(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test", c)
}

type config struct {
	Service     string
	Region      string
	Cluster     string
	Environment string
}

func Test_Unmarshal(t *testing.T) {
	tmp, err := os.MkdirTemp("", "porto-fileutil")
	require.NoError(t, err)
	defer os.RemoveAll(tmp)

	var v config
	err = fileutil.Unmarshal("testdata/test_config.yaml", &v)
	require.NoError(t, err)

	assert.Equal(t, "porto-pod", v.Service)
	assert.Equal(t, "local", v.Region)
	assert.Equal(t, "cl1", v.Cluster)
	assert.Equal(t, "test", v.Environment)

	fn := path.Join(tmp, "test_config.yaml")
	err = fileutil.Marshal(fn, &v)
	require.NoError(t, err)

	var v2 config
	err = fileutil.Unmarshal(fn, &v2)
	require.NoError(t, err)
	assert.Equal(t, v, v2)

	err = fileutil.Unmarshal("testdata/test_config.json", &v)
	require.NoError(t, err)

	assert.Equal(t, "porto-pod", v.Service)
	assert.Equal(t, "local", v.Region)
	assert.Equal(t, "cl1", v.Cluster)
	assert.Equal(t, "test", v.Environment)

	fn = path.Join(tmp, "test_config.json")
	err = fileutil.Marshal(fn, &v)
	require.NoError(t, err)
	encoded, err := os.ReadFile(fn)
	require.NoError(t, err)
	assert.Equal(t,
		`{
  "Service": "porto-pod",
  "Region": "local",
  "Cluster": "cl1",
  "Environment": "test"
}`,
		string(encoded))

	err = fileutil.Unmarshal(fn, &v2)
	require.NoError(t, err)
	assert.Equal(t, v, v2)
}
