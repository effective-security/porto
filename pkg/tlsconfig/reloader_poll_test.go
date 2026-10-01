package tlsconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes of the poll
// goroutine's logger and the test's reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestReloaderPollKeepsPairWhenFilesAreMissing is not parallel: it replaces
// the package ticker and installs a global log formatter.
func TestReloaderPollKeepsPairWhenFilesAreMissing(t *testing.T) {
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
	reloader, err := NewKeypairReloader("poll-missing", certPath, keyPath, time.Hour)
	require.NoError(t, err)
	current := reloader.Keypair()
	require.NotNil(t, current)

	logs := &syncBuffer{}
	removeFormatter := xlog.InstallFormatter(xlog.NewStringFormatter(logs))
	t.Cleanup(removeFormatter)

	require.NoError(t, os.Remove(certPath))
	require.NoError(t, os.Remove(keyPath))
	// no file is newer, so only a stale loadedAt makes the tick reload
	reloader.lock.Lock()
	reloader.loadedAt = time.Now().Add(-2 * time.Hour)
	reloader.lock.Unlock()

	select {
	case ticks <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatal("the poll goroutine did not receive the tick")
	}
	// the poll goroutine logs the failed reload last
	reloadErr := `err="count: 1: open ` + certPath
	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), reloadErr)
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, reloader.Close())
	select {
	case <-pollStopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop the poll goroutine")
	}
	removeFormatter()

	lines := strings.Split(logs.String(), "\n")
	countLines := func(substr string) int {
		n := 0
		for _, line := range lines {
			if strings.Contains(line, substr) {
				n++
			}
		}
		return n
	}
	// Each reload attempt logs a stat warning per missing file (statFiles)
	// and one LoadX509KeyPair warning; the poll loop logs one more stat
	// warning per file before it reloads.
	attempts := countLines("reason=LoadX509KeyPair label=poll-missing")
	require.Positive(t, attempts)
	for _, file := range []string{certPath, keyPath} {
		stat := `reason=stat label=poll-missing file="` + file + `" err="stat ` + file + `: no such file or directory"`
		assert.Equal(t, attempts+1, countLines(stat), "stat warnings for %s", file)
	}
	errLines := 0
	for _, line := range lines {
		if strings.Contains(line, reloadErr) {
			errLines++
			assert.Contains(t, line, "level=E ")
			assert.Contains(t, line, "label=poll-missing ")
		}
	}
	assert.Equal(t, 1, errLines, "the failed reload is logged once")
	assert.Equal(t, uint32(1), reloader.LoadedCount())
	assert.Same(t, current, reloader.Keypair(), "a failed reload keeps the previous pair")
}

func TestValidateCertificate(t *testing.T) {
	t.Parallel()

	validPEM, _, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	expiredPEM, _, err := testca.MakeSelfCertRSAPem(-1)
	require.NoError(t, err)
	der := func(p []byte) []byte {
		block, _ := pem.Decode(p)
		require.NotNil(t, block)
		return block.Bytes
	}
	validDER := der(validPEM)

	tcases := []struct {
		name string
		kp   *tls.Certificate
		err  string
	}{
		{name: "nil", kp: nil, err: "certificate chain is empty"},
		{name: "empty chain", kp: &tls.Certificate{}, err: "certificate chain is empty"},
		{name: "unparsable leaf", kp: &tls.Certificate{Certificate: [][]byte{[]byte("garbage")}}, err: "unable to parse certificate: x509: malformed certificate"},
		{name: "expired", kp: &tls.Certificate{Certificate: [][]byte{der(expiredPEM)}}, err: "certificate expired"},
		{name: "valid without leaf", kp: &tls.Certificate{Certificate: [][]byte{validDER}}},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateCertificate(tc.kp)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, tc.kp.Leaf, "the parsed leaf is stored")
			assert.Equal(t, validDER, tc.kp.Leaf.Raw)
		})
	}

	// a leaf that is already set is not parsed again
	leaf, err := x509.ParseCertificate(validDER)
	require.NoError(t, err)
	kp := &tls.Certificate{Certificate: [][]byte{[]byte("garbage")}, Leaf: leaf}
	require.NoError(t, validateCertificate(kp))
	assert.Same(t, leaf, kp.Leaf)
}

func TestKeypairReloaderWithoutPair(t *testing.T) {
	t.Parallel()

	k := &KeypairReloader{}
	assert.Nil(t, k.Keypair())
	pair, err := k.GetKeypairFunc()(nil)
	assert.Nil(t, pair)
	assert.EqualError(t, err, "certificate is unavailable")
	pair, err = k.GetClientCertificateFunc()(nil)
	assert.Nil(t, pair)
	assert.EqualError(t, err, "certificate is unavailable")
}
