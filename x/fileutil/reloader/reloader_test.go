package reloader_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/porto/x/fileutil/reloader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Reloader(t *testing.T) {
	now := time.Now().UTC()

	file := filepath.Join(os.TempDir(), "test-reloaded.txt")

	callbackCount := 0
	lastModifiedAt := time.Now()
	onChangedFunc := func(fn string, modifiedAt time.Time) {
		assert.Equal(t, file, fn)
		if callbackCount > 0 {
			assert.True(t, modifiedAt.After(lastModifiedAt), fmt.Sprintf("this=%v, last=%v", modifiedAt, lastModifiedAt))
		}
		lastModifiedAt = modifiedAt
		callbackCount++
	}

	err := ioutil.WriteFile(file, []byte("Test_Reloader"), os.ModePerm)
	require.NoError(t, err)

	k, err := reloader.NewReloader(file, 100*time.Millisecond, onChangedFunc)
	require.NoError(t, err)
	require.NotNil(t, k)
	defer k.Close()

	_ = k.Reload()

	loadedAt := k.LoadedAt()
	assert.True(t, loadedAt.After(now), "loaded time must be after test start time")
	assert.Equal(t, uint32(1), k.LoadedCount())

	err = ioutil.WriteFile(file, []byte("Test_Reloader2"), os.ModePerm)
	require.NoError(t, err)
	time.Sleep(2 * time.Millisecond)
	err = ioutil.WriteFile(file, []byte("Test_Reloader3"), os.ModePerm)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	loadedAt2 := k.LoadedAt()
	count := int(k.LoadedCount())
	assert.Equal(t, callbackCount, count)
	assert.True(t, count >= 2 && count <= 4, "must be loaded at start, whithin period and after, loaded: %d", k.LoadedCount())
	assert.True(t, loadedAt2.After(loadedAt), "re-loaded time must be after last loaded time")

	err = ioutil.WriteFile(file, []byte("Test_Reloader4"), os.ModePerm)
	require.NoError(t, err)
	time.Sleep(2 * time.Millisecond)
	err = ioutil.WriteFile(file, []byte("Test_Reloader5"), os.ModePerm)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	loadedAt3 := k.LoadedAt()
	count = int(k.LoadedCount())
	assert.Equal(t, callbackCount, count)
	assert.True(t, count >= 3 && count <= 5, "must be loaded at start, whithin period and after, loaded: %d", k.LoadedCount())
	assert.True(t, loadedAt3.After(loadedAt2), "re-loaded time must be after last loaded time")
}

func Test_ReloaderClose(t *testing.T) {
	var k *reloader.Reloader
	assert.NotPanics(t, func() {
		k.Close()
	})

	file := filepath.Join(os.TempDir(), "test-reloaded.txt")

	k, err := reloader.NewReloader(file, 100*time.Millisecond, func(fn string, modifiedAt time.Time) {})
	require.NoError(t, err)
	require.NotNil(t, k)

	err = k.Close()
	assert.NoError(t, err)

	err = k.Close()
	require.Error(t, err)
	assert.Equal(t, "already closed", err.Error())
}
