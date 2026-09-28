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

// errReloaderClosed is returned by Reload after Close. The poll goroutine
// treats it as a stop signal rather than a failure.
var errReloaderClosed = errors.New("reloader closed")

// OnReloadFunc is invoked, in its own goroutine, with the newly loaded
// certificate each time the certificate file's modification time changes.
type OnReloadFunc func(pair *tls.Certificate)

// KeypairReloader loads a TLS certificate/key pair from files and reloads it
// in a background goroutine when either file's modification time changes, or
// at least once per hour. Obtain the current pair via Keypair, GetKeypairFunc
// (server) or GetClientCertificateFunc (client). Close stops the goroutine.
// Expired certificates are rejected; a failed reload keeps the previous pair.
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
	reloadDone     chan struct{}
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
					// errReloaderClosed means Close is waiting for an active
					// reload and stopChan closes next; it is not a failure.
					if err != nil && !errors.Is(err, errReloaderClosed) {
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
// times with a 100ms sleep before each attempt outside the write lock,
// and notifies OnReload handlers if the certificate's mtime changed. If
// another Reload is in progress, it waits for that one and then loads again,
// so a nil return means the pair was read after the call started. On failure
// the previous pair is kept. Reload returns an error after Close.
func (k *KeypairReloader) Reload() error {
	k.lock.Lock()
	// Do not skip when a reload is active: it may have read the files before
	// the caller changed them.
	for k.inProgress && !k.closed {
		done := k.reloadDone
		k.lock.Unlock()
		<-done
		k.lock.Lock()
	}
	if k.closed {
		k.lock.Unlock()
		return errors.WithStack(errReloaderClosed)
	}
	k.inProgress = true
	k.reloadDone = make(chan struct{})
	k.lock.Unlock()

	defer func() {
		k.lock.Lock()
		k.inProgress = false
		close(k.reloadDone)
		k.reloadDone = nil
		k.lock.Unlock()
	}()

	var newCert *tls.Certificate
	var certFileInfo, keyFileInfo os.FileInfo
	var err error

	for i := 0; i < 3; i++ {
		// sleep a little as notification occurs right after process starts writing the file,
		// so it needs to finish writing the file
		time.Sleep(100 * time.Millisecond)
		// stat before reading: a write that lands during the load then leaves
		// a newer mtime on disk, and the next poll reloads it
		certFileInfo, keyFileInfo = k.statFiles()
		newCert, err = LoadX509KeyPairWithOCSP(k.certPath, k.keyPath)
		if err == nil {
			err = validateCertificate(newCert)
		}
		if err == nil {
			break
		}
		logger.KV(xlog.WARNING, "reason", "LoadX509KeyPair", "label", k.label, "file", k.certPath, "err", err.Error())
	}
	if err != nil {
		return errors.WithMessagef(err, "count: %d", atomic.LoadUint32(&k.count))
	}

	k.lock.Lock()
	oldModifiedAt := k.certModifiedAt
	if certFileInfo != nil {
		k.certModifiedAt = certFileInfo.ModTime()
	}
	if keyFileInfo != nil {
		k.keyModifiedAt = keyFileInfo.ModTime()
	}
	k.loadedAt = time.Now().UTC()
	k.keypair = newCert
	count := atomic.AddUint32(&k.count, 1)
	modifiedAt := k.certModifiedAt
	handlers := append([]OnReloadFunc(nil), k.handlers...)
	k.lock.Unlock()

	if oldModifiedAt != modifiedAt {
		logger.KV(xlog.DEBUG, "label", k.label, "count", count, "cert", k.certPath, "modifiedAt", modifiedAt.Format(time.RFC3339))

		// execute notifications outside of the lock
		for _, h := range handlers {
			go h(newCert)
		}
	}

	return nil
}

// statFiles returns the certificate and key file info. A file that cannot be
// stat'ed is logged and returned as nil, which keeps its previous mtime.
func (k *KeypairReloader) statFiles() (certInfo, keyInfo os.FileInfo) {
	certInfo, err := os.Stat(k.certPath)
	if err != nil {
		logger.KV(xlog.WARNING, "reason", "stat", "label", k.label, "file", k.certPath, "err", err.Error())
	}
	keyInfo, err = os.Stat(k.keyPath)
	if err != nil {
		logger.KV(xlog.WARNING, "reason", "stat", "label", k.label, "file", k.keyPath, "err", err.Error())
	}
	return certInfo, keyInfo
}

func validateCertificate(kp *tls.Certificate) error {
	if kp == nil || len(kp.Certificate) == 0 {
		return errors.New("certificate chain is empty")
	}
	if kp.Leaf == nil {
		leaf, err := x509.ParseCertificate(kp.Certificate[0])
		if err != nil {
			return errors.WithMessage(err, "unable to parse certificate")
		}
		kp.Leaf = leaf
	}
	if !time.Now().Before(kp.Leaf.NotAfter) {
		return errors.New("certificate expired")
	}
	return nil
}

func (k *KeypairReloader) tlsCert() (*tls.Certificate, error) {
	kp := k.keypair
	if kp == nil || kp.Leaf == nil {
		return nil, errors.New("certificate is unavailable")
	}
	if !time.Now().Before(kp.Leaf.NotAfter) {
		err := errors.New("certificate expired")
		logger.KV(xlog.ERROR, "label", k.label, "count", atomic.LoadUint32(&k.count), "cert", k.certPath, "err", err)
		return nil, err
	}
	if kp.Leaf.NotAfter.Before(time.Now().Add(time.Hour)) {
		logger.KV(xlog.WARNING, "label", k.label, "count", atomic.LoadUint32(&k.count), "cert", k.certPath, "expires_soon", kp.Leaf.NotAfter.Format(time.RFC3339))
	}
	return kp, nil
}

// GetKeypairFunc returns a function suitable for tls.Config.GetCertificate
// that serves the current pair or returns an error if it has expired.
func (k *KeypairReloader) GetKeypairFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		k.lock.RLock()
		defer k.lock.RUnlock()
		return k.tlsCert()
	}
}

// GetClientCertificateFunc returns a function suitable for
// tls.Config.GetClientCertificate that serves the current pair.
// It returns an error if the pair has expired.
func (k *KeypairReloader) GetClientCertificateFunc() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		k.lock.RLock()
		defer k.lock.RUnlock()
		return k.tlsCert()
	}
}

// Keypair returns the current pair, or nil on a nil receiver.
// It returns nil if the pair has expired.
func (k *KeypairReloader) Keypair() *tls.Certificate {
	if k == nil {
		return nil
	}
	k.lock.RLock()
	defer k.lock.RUnlock()

	kp, _ := k.tlsCert()
	return kp
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

// Close waits for an active reload, then signals the polling goroutine to
// stop without waiting for that goroutine to exit. It is nil-safe and returns
// an error on a second call.
func (k *KeypairReloader) Close() error {
	if k == nil {
		return nil
	}

	k.lock.Lock()
	if k.closed {
		k.lock.Unlock()
		return errors.New("already closed")
	}
	k.closed = true
	reloadDone := k.reloadDone
	k.lock.Unlock()
	if reloadDone != nil {
		<-reloadDone
	}

	close(k.stopChan)

	return nil
}
