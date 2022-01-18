package fileutil_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/effective-security/porto/x/fileutil"
	"github.com/effective-security/porto/x/guid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FolderExists(t *testing.T) {
	tmpDir := path.Join(os.TempDir(), "fileutil-test", guid.MustCreate())

	err := os.MkdirAll(tmpDir, os.ModePerm)
	require.NoError(t, err)

	defer os.RemoveAll(tmpDir)

	assert.Error(t, fileutil.FolderExists(""))
	assert.NoError(t, fileutil.FolderExists(tmpDir))

	err = fileutil.FolderExists(tmpDir + "/a")
	require.Error(t, err)
	assert.Equal(t, fmt.Sprintf("stat %s: no such file or directory", tmpDir+"/a"), err.Error())

	err = fileutil.FolderExists("./folders.go")
	require.Error(t, err)
	assert.Equal(t, "not a folder: \"./folders.go\"", err.Error())
}

func Test_FileExists(t *testing.T) {
	tmpDir := path.Join(os.TempDir(), "fileutil-test", guid.MustCreate())

	err := os.MkdirAll(tmpDir, os.ModePerm)
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	file := path.Join(tmpDir, "file.txt")
	err = ioutil.WriteFile(file, []byte("FileExists"), 0644)
	require.NoError(t, err)

	assert.Error(t, fileutil.FileExists(""))
	assert.NoError(t, fileutil.FileExists(file))

	err = fileutil.FileExists(tmpDir)
	require.Error(t, err)
	assert.Equal(t, fmt.Sprintf("not a file: %q", tmpDir), err.Error())

	err = fileutil.FileExists(tmpDir + "/a")
	require.Error(t, err)
	assert.Equal(t, fmt.Sprintf("stat %s: no such file or directory", tmpDir+"/a"), err.Error())
}
