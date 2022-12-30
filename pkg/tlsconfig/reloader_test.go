package tlsconfig_test

import (
	"crypto/tls"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_KeypairReloader(t *testing.T) {
	now := time.Now().UTC()
	pemCert, pemKey, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	require.NotNil(t, pemCert)
	require.NotNil(t, pemKey)

	pemFile := filepath.Join(os.TempDir(), "test-KeypairReloader.pem")
	keyFile := filepath.Join(os.TempDir(), "test-KeypairReloader-key.pem")

	err = ioutil.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = ioutil.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	k, err := tlsconfig.NewKeypairReloader("", pemFile, keyFile, 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, k)
	defer k.Close()

	reloadedCount := 0
	k.OnReload(func(_ *tls.Certificate) {
		reloadedCount++
	})

	loadedAt := k.LoadedAt()
	assert.True(t, loadedAt.After(now), "loaded time must be after test start time")
	assert.Equal(t, uint32(1), k.LoadedCount())

	err = ioutil.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = ioutil.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)
	err = ioutil.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	loadedAt2 := k.LoadedAt()
	count := int(k.LoadedCount())
	assert.True(t, count >= 2 && count <= 4, "must be loaded at start, whithin period and after, loaded: %d", k.LoadedCount())
	assert.True(t, loadedAt2.After(loadedAt), "re-loaded time must be after last loaded time")

	err = ioutil.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = ioutil.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	err = ioutil.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = ioutil.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	loadedAt3 := k.LoadedAt()
	count = int(k.LoadedCount())
	assert.True(t, count >= 3 && count <= 5, "must be loaded at start, whithin period and after, loaded: %d", k.LoadedCount())
	assert.True(t, loadedAt3.After(loadedAt2), "re-loaded time must be after last loaded time")
	assert.True(t, reloadedCount > 1, "must be reloaded when file modified: %d", reloadedCount)

	getKeypair := k.GetKeypairFunc()
	kpair, err := getKeypair(nil)
	require.NoError(t, err)
	require.NotNil(t, kpair)

	getClientCertificate := k.GetClientCertificateFunc()
	kpair, err = getClientCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, kpair)
}

func Test_KeypairReloader_Reload(t *testing.T) {
	pemCert, pemKey, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	require.NotNil(t, pemCert)
	require.NotNil(t, pemKey)

	pemFile := filepath.Join(os.TempDir(), "test-KeypairReloader2.pem")
	keyFile := filepath.Join(os.TempDir(), "test-KeypairReloader2-key.pem")

	err = ioutil.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = ioutil.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)

	k, err := tlsconfig.NewKeypairReloader("test", pemFile, keyFile, 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, k)
	defer k.Close()

	reloadedCount := 0
	k.OnReload(func(_ *tls.Certificate) {
		reloadedCount++
	})

	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = k.Reload()
		}()
	}
	wg.Wait()
	assert.Equal(t, 0, reloadedCount)
}
