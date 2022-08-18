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

func Test_SubfolderNames(t *testing.T) {
	l, err := fileutil.SubfolderNames(".")
	require.NoError(t, err)
	assert.Len(t, l, 3)

	_, err = fileutil.SubfolderNames("./notfound")
	assert.EqualError(t, err, "open ./notfound: no such file or directory")

	_, err = fileutil.SubfolderNames("./folders.go")
	assert.EqualError(t, err, "readdirent ./folders.go: not a directory")
}

func Test_FileNames(t *testing.T) {
	l, err := fileutil.FileNames("./resolve")
	require.NoError(t, err)
	assert.Len(t, l, 2)

	_, err = fileutil.FileNames("./notfound")
	assert.EqualError(t, err, "open ./notfound: no such file or directory")
}
