package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

// makeTicker wraps time.NewTicker so tests can override the poll clock.
var makeTicker = func(interval time.Duration) (func(), <-chan time.Time) {
	t := time.NewTicker(interval)
	return t.Stop, t.C
}

// OnReloadFunc is invoked, in its own goroutine, with the newly loaded
// certificate each time the certificate file's modification time changes.
type OnReloadFunc func(pair *tls.Certificate)

// KeypairReloader loads a TLS certificate/key pair from files and reloads it
// in a background goroutine when either file's modification time changes, or
// at least once per hour. Obtain the current pair via Keypair, GetKeypairFunc
// (server) or GetClientCertificateFunc (client). Close stops the goroutine.
// Serving an expired certificate panics via the package logger.
type KeypairReloader struct {
	label          string
	lock           sync.RWMutex
	loadedAt       time.Time
	count          uint32
	keypair        *tls.Certificate
	certPath       string
	certModifiedAt time.Time
	keyPath        string
	keyModifiedAt  time.Time
	inProgress     bool
	stopChan       chan<- struct{}
	closed         bool
	handlers       []OnReloadFunc
}

// NewKeypairReloader loads the pair once (returning an error on failure) and
// starts a goroutine that polls the files every checkInterval. label is used
// in logs and defaults to the certificate file's base name. The initial load
// includes a fixed 100ms delay. The caller must call Close.
func NewKeypairReloader(label, certPath, keyPath string, checkInterval time.Duration) (*KeypairReloader, error) {
	if label == "" {
		label = path.Base(certPath)
	}

	result := &KeypairReloader{
		label:    label,
		certPath: certPath,
		keyPath:  keyPath,
		stopChan: make(chan struct{}),
	}

	logger.KV(xlog.TRACE, "label", label, "status", "started")

	err := result.Reload()
	if err != nil {
		return nil, err
	}

	stopChan := make(chan struct{})
	tickerStop, tickChan := makeTicker(checkInterval)
	go func() {
		for {
			select {
			case <-stopChan:
				tickerStop()
				logger.KV(xlog.TRACE, "status", "closed", "label", result.label, "count", result.LoadedCount())
				return
			case <-tickChan:
				certModifiedAt, keyModifiedAt, loadedAt := result.snapshotTimes()
				modified := false
				fi, err := os.Stat(certPath)
				if err == nil {
					modified = fi.ModTime().After(certModifiedAt)
				} else {
					logger.KV(xlog.WARNING, "reason", "stat", "label", result.label, "file", certPath, "err", err)
				}
				if !modified {
					fi, err = os.Stat(keyPath)
					if err == nil {
						modified = fi.ModTime().After(keyModifiedAt)
					} else {
						logger.KV(xlog.WARNING, "reason", "stat", "label", result.label, "file", keyPath, "err", err)
					}
				}
				// reload on modified, or force to reload each hour
				if modified || loadedAt.Add(1*time.Hour).Before(time.Now().UTC()) {
					err := result.Reload()
					if err != nil {
						logger.KV(xlog.ERROR, "label", result.label, "err", err)
					}
				}
			}
		}
	}()
	result.stopChan = stopChan
	return result, nil
}

// snapshotTimes returns the file modification and load timestamps under the
// read lock so the poll goroutine never races with Reload.
func (k *KeypairReloader) snapshotTimes() (certModifiedAt, keyModifiedAt, loadedAt time.Time) {
	k.lock.RLock()
	defer k.lock.RUnlock()
	return k.certModifiedAt, k.keyModifiedAt, k.loadedAt
}

// OnReload registers a handler called after each reload that changed the
// certificate file's modification time. A nil handler is ignored.
func (k *KeypairReloader) OnReload(f OnReloadFunc) *KeypairReloader {
	k.lock.Lock()
	defer k.lock.Unlock()

	if f != nil {
		k.handlers = append(k.handlers, f)
	}
	return k
}

// Reload synchronously re-reads the pair from disk, retrying up to three
// times with a 100ms sleep before each attempt while holding the write lock,
// and notifies OnReload handlers if the certificate's mtime changed. It is a
// no-op returning nil if another Reload is in progress. On failure the
// previous pair is kept.
func (k *KeypairReloader) Reload() error {
	k.lock.Lock()
	if k.inProgress {
		k.lock.Unlock()
		return nil
	}

	k.inProgress = true
	defer func() {
		k.inProgress = false
		k.lock.Unlock()
	}()

	oldModifiedAt := k.certModifiedAt

	var newCert *tls.Certificate
	var err error

	for i := 0; i < 3; i++ {
		// sleep a little as notification occurs right after process starts writing the file,
		// so it needs to finish writing the file
		time.Sleep(100 * time.Millisecond)
		newCert, err = LoadX509KeyPairWithOCSP(k.certPath, k.keyPath)
		if err == nil {
			break
		}
		logger.KV(xlog.WARNING, "reason", "LoadX509KeyPair", "label", k.label, "file", k.certPath, "err", err.Error())
	}
	if err != nil {
		return errors.WithMessagef(err, "count: %d", atomic.LoadUint32(&k.count))
	}

	atomic.AddUint32(&k.count, 1)
	k.loadedAt = time.Now().UTC()

	certFileInfo, err := os.Stat(k.certPath)
	if err == nil {
		k.certModifiedAt = certFileInfo.ModTime()
	} else {
		logger.KV(xlog.WARNING, "reason", "stat", "label", k.label, "file", k.certPath, "err", err.Error())
	}

	keyFileInfo, err := os.Stat(k.keyPath)
	if err == nil {
		k.keyModifiedAt = keyFileInfo.ModTime()
	} else {
		logger.KV(xlog.WARNING, "reason", "stat", "label", k.label, "file", k.keyPath, "err", err.Error())
	}

	k.keypair = newCert
	keypair := k.tlsCert()

	if oldModifiedAt != k.certModifiedAt {
		logger.KV(xlog.DEBUG, "label", k.label, "count", atomic.LoadUint32(&k.count), "cert", k.certPath, "modifiedAt", k.certModifiedAt.Format(time.RFC3339))

		// execute notifications outside of the lock
		for _, h := range k.handlers {
			go h(keypair)
		}
	}

	return nil
}

func (k *KeypairReloader) tlsCert() *tls.Certificate {
	var err error
	kp := k.keypair
	if kp.Leaf == nil && len(kp.Certificate) > 0 {
		kp.Leaf, err = x509.ParseCertificate(kp.Certificate[0])
		if err != nil {
			logger.KV(xlog.WARNING, "reason", "ParseCertificate", "label", k.label, "err", err.Error())
		}
	}

	if kp.Leaf != nil {
		now := time.Now()
		if kp.Leaf.NotAfter.Before(now) {
			logger.KV(xlog.ERROR, "label", k.label, "count", atomic.LoadUint32(&k.count), "cert", k.certPath, "expired", kp.Leaf.NotAfter.Format(time.RFC3339))
			logger.Panic("cert expired")
		} else if kp.Leaf.NotAfter.Before(now.Add(1 * time.Hour)) {
			logger.KV(xlog.WARNING, "label", k.label, "count", atomic.LoadUint32(&k.count), "cert", k.certPath, "expires_soon", kp.Leaf.NotAfter.Format(time.RFC3339))
		}
	}
	return kp
}

// GetKeypairFunc returns a function suitable for tls.Config.GetCertificate
// that serves the current pair. It panics if the pair has expired.
func (k *KeypairReloader) GetKeypairFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		k.lock.RLock()
		defer k.lock.RUnlock()
		return k.tlsCert(), nil
	}
}

// GetClientCertificateFunc returns a function suitable for
// tls.Config.GetClientCertificate that serves the current pair.
// It panics if the pair has expired.
func (k *KeypairReloader) GetClientCertificateFunc() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		k.lock.RLock()
		defer k.lock.RUnlock()
		return k.tlsCert(), nil
	}
}

// Keypair returns the current pair, or nil on a nil receiver.
// It panics if the pair has expired.
func (k *KeypairReloader) Keypair() *tls.Certificate {
	if k == nil {
		return nil
	}
	k.lock.RLock()
	defer k.lock.RUnlock()

	return k.tlsCert()
}

// CertAndKeyFiles returns the certificate and key file paths being watched.
func (k *KeypairReloader) CertAndKeyFiles() (string, string) {
	if k == nil {
		return "", ""
	}
	k.lock.RLock()
	defer k.lock.RUnlock()

	return k.certPath, k.keyPath
}

// LoadedAt returns the UTC time of the last successful load.
func (k *KeypairReloader) LoadedAt() time.Time {
	k.lock.RLock()
	defer k.lock.RUnlock()

	return k.loadedAt
}

// LoadedCount returns the number of successful loads, including the first.
func (k *KeypairReloader) LoadedCount() uint32 {
	return atomic.LoadUint32(&k.count)
}

// Close stops the polling goroutine, blocking until it acknowledges. It is
// nil-safe and returns an error on a second call.
func (k *KeypairReloader) Close() error {
	if k == nil {
		return nil
	}

	// Take the write lock so Close waits for an in-flight Reload instead of
	// blocking it: sending on stopChan while holding a read lock deadlocked
	// when the poll goroutine was waiting for the write lock in Reload.
	k.lock.Lock()
	if k.closed {
		k.lock.Unlock()
		return errors.New("already closed")
	}
	k.closed = true
	k.lock.Unlock()

	// closing (rather than sending) never blocks; the poll goroutine
	// observes it on its next select.
	close(k.stopChan)

	return nil
}
