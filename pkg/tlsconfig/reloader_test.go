package tlsconfig_test

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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

	tmpDir := t.TempDir()
	pemFile := filepath.Join(tmpDir, "test-KeypairReloader.pem")
	keyFile := filepath.Join(tmpDir, "test-KeypairReloader-key.pem")

	err = os.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	k, err := tlsconfig.NewKeypairReloader("", pemFile, keyFile, 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, k)
	defer k.Close()

	var reloadedCount atomic.Int32
	k.OnReload(func(_ *tls.Certificate) {
		reloadedCount.Add(1)
	})

	loadedAt := k.LoadedAt()
	assert.True(t, loadedAt.After(now), "loaded time must be after test start time")
	assert.Equal(t, uint32(1), k.LoadedCount())

	err = os.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)
	err = os.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)

	require.Eventually(t, func() bool { return k.LoadedCount() >= 2 }, 2*time.Second, 10*time.Millisecond)

	loadedAt2 := k.LoadedAt()
	count := int(k.LoadedCount())
	assert.GreaterOrEqual(t, count, 2)
	assert.True(t, loadedAt2.After(loadedAt), "re-loaded time must be after last loaded time")

	err = os.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	err = os.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)

	require.Eventually(t, func() bool { return k.LoadedCount() >= 3 && reloadedCount.Load() > 1 }, 2*time.Second, 10*time.Millisecond)

	loadedAt3 := k.LoadedAt()
	count = int(k.LoadedCount())
	assert.GreaterOrEqual(t, count, 3)
	assert.True(t, loadedAt3.After(loadedAt2), "re-loaded time must be after last loaded time")
	assert.True(t, reloadedCount.Load() > 1, "must be reloaded when file modified: %d", reloadedCount.Load())

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

	tmpDir := t.TempDir()
	pemFile := filepath.Join(tmpDir, "test-KeypairReloader2.pem")
	keyFile := filepath.Join(tmpDir, "test-KeypairReloader2-key.pem")

	err = os.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)

	k, err := tlsconfig.NewKeypairReloader("test", pemFile, keyFile, 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, k)
	defer k.Close()

	var reloadedCount atomic.Int32
	k.OnReload(func(_ *tls.Certificate) {
		reloadedCount.Add(1)
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
	assert.Equal(t, int32(0), reloadedCount.Load())
}
