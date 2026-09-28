package tlsconfig

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestPair(t *testing.T, cert, key []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, cert, 0600))
	require.NoError(t, os.WriteFile(keyPath, key, 0600))
	return certPath, keyPath
}

func TestB02ExpiredCertificate(t *testing.T) {
	t.Parallel()
	validCert, validKey, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	expiredCert, expiredKey, err := testca.MakeSelfCertRSAPem(-1)
	require.NoError(t, err)
	certPath, keyPath := writeTestPair(t, expiredCert, expiredKey)

	reloader, err := NewKeypairReloader("", certPath, keyPath, time.Hour)
	require.ErrorContains(t, err, "certificate expired")
	assert.Nil(t, reloader)

	require.NoError(t, os.WriteFile(certPath, validCert, 0600))
	require.NoError(t, os.WriteFile(keyPath, validKey, 0600))
	reloader, err = NewKeypairReloader("", certPath, keyPath, time.Hour)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reloader.Close()) })
	current := reloader.Keypair()
	require.NotNil(t, current)

	require.NoError(t, os.WriteFile(certPath, expiredCert, 0600))
	require.NoError(t, os.WriteFile(keyPath, expiredKey, 0600))
	err = reloader.Reload()
	require.ErrorContains(t, err, "certificate expired")
	assert.Equal(t, uint32(1), reloader.LoadedCount())
	assert.Same(t, current, reloader.Keypair())

	reloader.lock.Lock()
	leaf := *current.Leaf
	leaf.NotAfter = time.Now().Add(-time.Minute)
	current.Leaf = &leaf
	reloader.lock.Unlock()
	serverCert, err := reloader.GetKeypairFunc()(nil)
	assert.Nil(t, serverCert)
	assert.ErrorContains(t, err, "certificate expired")
	clientCert, err := reloader.GetClientCertificateFunc()(nil)
	assert.Nil(t, clientCert)
	assert.ErrorContains(t, err, "certificate expired")
	assert.Nil(t, reloader.Keypair())
}

func TestB02ReloadLeavesHandshakeReadsAvailable(t *testing.T) {
	t.Parallel()
	cert, key, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	certPath, keyPath := writeTestPair(t, cert, key)
	reloader, err := NewKeypairReloader("", certPath, keyPath, time.Hour)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reloader.Close()) })

	require.NoError(t, os.WriteFile(certPath, []byte("invalid"), 0600))
	reloadDone := make(chan error, 1)
	go func() { reloadDone <- reloader.Reload() }()
	require.Eventually(t, func() bool {
		if !reloader.lock.TryRLock() {
			return false
		}
		inProgress := reloader.inProgress
		reloader.lock.RUnlock()
		return inProgress
	}, time.Second, time.Millisecond)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pair, getErr := reloader.GetKeypairFunc()(nil)
			assert.NoError(t, getErr)
			assert.NotNil(t, pair)
		}()
	}
	wg.Wait()
	require.Error(t, <-reloadDone)
	assert.Equal(t, uint32(1), reloader.LoadedCount())
}

func TestB02CloseWaitsForReload(t *testing.T) {
	t.Parallel()
	cert, key, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	certPath, keyPath := writeTestPair(t, cert, key)
	reloader, err := NewKeypairReloader("", certPath, keyPath, time.Hour)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reloader.Close() })
	require.NoError(t, os.WriteFile(certPath, []byte("invalid"), 0600))

	reloadResult := make(chan error, 1)
	go func() { reloadResult <- reloader.Reload() }()
	var reloadDone <-chan struct{}
	require.Eventually(t, func() bool {
		reloader.lock.RLock()
		reloadDone = reloader.reloadDone
		reloader.lock.RUnlock()
		return reloadDone != nil
	}, time.Second, time.Millisecond)

	closeResult := make(chan error, 1)
	go func() { closeResult <- reloader.Close() }()
	require.NoError(t, <-closeResult)
	select {
	case <-reloadDone:
	default:
		t.Fatal("Close returned before Reload completed")
	}
	require.Error(t, <-reloadResult)
	assert.ErrorContains(t, reloader.Reload(), "reloader closed")
}

func TestB02HTTPTransportUsesStableTLSConfig(t *testing.T) {
	t.Parallel()
	firstCert, firstKey, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	secondCert, secondKey, err := testca.MakeSelfCertRSAPem(2)
	require.NoError(t, err)
	certPath, keyPath := writeTestPair(t, firstCert, firstKey)
	userTLSConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	userTransport := &http.Transport{TLSClientConfig: userTLSConfig}
	tr, err := NewHTTPTransportWithReloader(certPath, keyPath, "", time.Hour, userTransport)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, tr.Close()) })
	assert.Same(t, userTLSConfig, userTransport.TLSClientConfig)
	initialConfig := tr.transport.TLSClientConfig
	require.NotNil(t, initialConfig)
	firstPair, err := initialConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.NotNil(t, firstPair)

	require.NoError(t, os.WriteFile(certPath, secondCert, 0600))
	require.NoError(t, os.WriteFile(keyPath, secondKey, 0600))
	require.NoError(t, tr.reloader.Reload())
	secondPair, err := initialConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.NotNil(t, secondPair)
	assert.False(t, bytes.Equal(firstPair.Certificate[0], secondPair.Certificate[0]))
	assert.Same(t, initialConfig, tr.transport.TLSClientConfig)
	assert.Same(t, userTLSConfig, userTransport.TLSClientConfig)
}

func TestB02RejectInvalidCABundles(t *testing.T) {
	t.Parallel()
	cert, key, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	certPath, keyPath := writeTestPair(t, cert, key)
	invalidCA := filepath.Join(t.TempDir(), "invalid-ca.pem")
	require.NoError(t, os.WriteFile(invalidCA, []byte("invalid"), 0600))

	_, err = NewServerTLSFromFiles(certPath, keyPath, invalidCA, "", tls.NoClientCert)
	assert.ErrorContains(t, err, "contains no valid certificates")
	_, err = NewServerTLSFromFiles(certPath, keyPath, "", invalidCA, tls.NoClientCert)
	assert.ErrorContains(t, err, "contains no valid certificates")
	_, err = NewClientTLSFromFiles("", "", invalidCA)
	assert.ErrorContains(t, err, "contains no valid certificates")
}

// holdReload marks a reload as in progress without running one, so a test
// decides when it finishes. The returned func finishes it.
func holdReload(reloader *KeypairReloader) func() {
	done := make(chan struct{})
	reloader.lock.Lock()
	reloader.inProgress = true
	reloader.reloadDone = done
	reloader.lock.Unlock()
	return func() {
		reloader.lock.Lock()
		reloader.inProgress = false
		reloader.reloadDone = nil
		close(done)
		reloader.lock.Unlock()
	}
}

func TestB02ReloadWaitsForActiveReload(t *testing.T) {
	t.Parallel()
	firstCert, firstKey, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	secondCert, secondKey, err := testca.MakeSelfCertRSAPem(2)
	require.NoError(t, err)
	secondPair, err := tls.X509KeyPair(secondCert, secondKey)
	require.NoError(t, err)
	certPath, keyPath := writeTestPair(t, firstCert, firstKey)
	reloader, err := NewKeypairReloader("", certPath, keyPath, time.Hour)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reloader.Close()) })

	// The active reload may already have read the first pair, so a Reload
	// issued after the files change must load them itself.
	finishActive := holdReload(reloader)
	require.NoError(t, os.WriteFile(certPath, secondCert, 0600))
	require.NoError(t, os.WriteFile(keyPath, secondKey, 0600))
	reloadResult := make(chan error, 1)
	go func() { reloadResult <- reloader.Reload() }()
	select {
	case err = <-reloadResult:
		finishActive()
		t.Fatalf("Reload returned %v while another reload was in progress", err)
	case <-time.After(50 * time.Millisecond):
	}

	finishActive()
	require.NoError(t, <-reloadResult)
	assert.Equal(t, uint32(2), reloader.LoadedCount())
	current := reloader.Keypair()
	require.NotNil(t, current)
	assert.Equal(t, secondPair.Certificate[0], current.Certificate[0])
}

func TestB02ConcurrentReloadsAllLoad(t *testing.T) {
	t.Parallel()
	cert, key, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	certPath, keyPath := writeTestPair(t, cert, key)
	reloader, err := NewKeypairReloader("", certPath, keyPath, time.Hour)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reloader.Close()) })

	const callers = 4
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() { assert.NoError(t, reloader.Reload()) })
	}
	wg.Wait()
	assert.Equal(t, uint32(callers+1), reloader.LoadedCount())
}

// TestB02PollDuringCloseLogsNoError is not parallel: it replaces the
// package ticker and the global log formatter.
func TestB02PollDuringCloseLogsNoError(t *testing.T) {
	ticks := make(chan time.Time)
	pollStopped := make(chan struct{})
	origTicker := makeTicker
	makeTicker = func(time.Duration) (func(), <-chan time.Time) {
		return func() { close(pollStopped) }, ticks
	}
	t.Cleanup(func() { makeTicker = origTicker })

	cert, key, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	certPath, keyPath := writeTestPair(t, cert, key)
	reloader, err := NewKeypairReloader("", certPath, keyPath, time.Hour)
	require.NoError(t, err)

	var logs bytes.Buffer
	removeFormatter := xlog.InstallFormatter(xlog.NewStringFormatter(&logs))
	t.Cleanup(removeFormatter)

	// Close waits for the held reload, so the tick lands after closed is set
	// and before stopChan is closed. A stale loadedAt makes the tick reload.
	finishActive := holdReload(reloader)
	reloader.lock.Lock()
	reloader.loadedAt = time.Now().Add(-2 * time.Hour)
	reloader.lock.Unlock()
	closeResult := make(chan error, 1)
	go func() { closeResult <- reloader.Close() }()
	require.Eventually(t, func() bool {
		reloader.lock.RLock()
		defer reloader.lock.RUnlock()
		return reloader.closed
	}, time.Second, time.Millisecond)

	ticks <- time.Now()
	finishActive()
	require.NoError(t, <-closeResult)
	<-pollStopped
	// removal waits for in-flight log calls, so logs is safe to read after it
	removeFormatter()
	assert.NotContains(t, logs.String(), "reloader closed")
}
