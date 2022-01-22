package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
)

// Wrap time.Tick so we can override it in tests.
var makeTicker = func(interval time.Duration) (func(), <-chan time.Time) {
	t := time.NewTicker(interval)
	return t.Stop, t.C
}

// OnReloadFunc is a callback to handle cert reload
type OnReloadFunc func(pair *tls.Certificate)

// KeypairReloader keeps necessary info to provide reloaded certificate
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

// NewKeypairReloader return an instance of the TLS cert loader
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

	logger.Tracef("label=%s, status=started", label)

	err := result.Reload()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	stopChan := make(chan struct{})
	tickerStop, tickChan := makeTicker(checkInterval)
	go func() {
		for {
			select {
			case <-stopChan:
				tickerStop()
				logger.Tracef("status=closed, label=%s, count=%d", result.label, result.LoadedCount())
				return
			case <-tickChan:
				modified := false
				fi, err := os.Stat(certPath)
				if err == nil {
					modified = fi.ModTime().After(result.certModifiedAt)
				} else {
					logger.Warningf("reason=stat, label=%s, file=%q, err=[%v]", result.label, certPath, err)
				}
				if !modified {
					fi, err = os.Stat(keyPath)
					if err == nil {
						modified = fi.ModTime().After(result.keyModifiedAt)
					} else {
						logger.Warningf("reason=stat, label=%s, file=%q, err=[%v]", result.label, keyPath, err)
					}
				}
				// reload on modified, or force to reload each hour
				if modified || result.loadedAt.Add(1*time.Hour).Before(time.Now().UTC()) {
					err := result.Reload()
					if err != nil {
						logger.Errorf("label=%s, err=[%+v]", result.label, err)
					}
				}
			}
		}
	}()
	result.stopChan = stopChan
	return result, nil
}

// OnReload allows to add OnReloadFunc handler
func (k *KeypairReloader) OnReload(f OnReloadFunc) *KeypairReloader {
	k.lock.Lock()
	defer k.lock.Unlock()

	if f != nil {
		k.handlers = append(k.handlers, f)
	}
	return k
}

// Reload will explicitly load TLS certs from the disk
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
		logger.Warningf("reason=LoadX509KeyPair, label=%s, file=%q, err=[%v]", k.label, k.certPath, err)
	}
	if err != nil {
		return errors.WithMessagef(err, "count: %d", k.count)
	}

	atomic.AddUint32(&k.count, 1)
	k.loadedAt = time.Now().UTC()

	certFileInfo, err := os.Stat(k.certPath)
	if err == nil {
		k.certModifiedAt = certFileInfo.ModTime()
	} else {
		logger.Warningf("reason=stat, label=%s, file=%q, err=[%v]", k.label, k.certPath, err)
	}

	keyFileInfo, err := os.Stat(k.keyPath)
	if err == nil {
		k.keyModifiedAt = keyFileInfo.ModTime()
	} else {
		logger.Warningf("reason=stat, label=%s, file=%q, err=[%v]", k.label, k.keyPath, err)
	}

	logger.Noticef("label=%s, count=%d, cert=%q, modifiedAt=%q",
		k.label, k.count, k.certPath, k.certModifiedAt.Format(time.RFC3339))

	k.keypair = newCert
	keypair := k.tlsCert()

	if oldModifiedAt != k.certModifiedAt {
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
			logger.Warningf("reason=ParseCertificate, label=%s, err=[%v]", k.label, err)
		}
	}

	if kp.Leaf != nil && kp.Leaf.NotAfter.Add(1*time.Hour).Before(time.Now().UTC()) {
		logger.Warningf("label=%s, count=%d, cert=%q, expires=%q",
			k.label, k.count, k.certPath, kp.Leaf.NotAfter.Format(time.RFC3339))
	}
	return kp
}

// GetKeypairFunc is a callback for TLSConfig to provide TLS certificate and key pair for Server
func (k *KeypairReloader) GetKeypairFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		k.lock.RLock()
		defer k.lock.RUnlock()
		return k.tlsCert(), nil
	}
}

// GetClientCertificateFunc is a callback for TLSConfig to provide TLS certificate and key pair for Client
func (k *KeypairReloader) GetClientCertificateFunc() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		k.lock.RLock()
		defer k.lock.RUnlock()
		return k.tlsCert(), nil
	}
}

// Keypair returns current pair
func (k *KeypairReloader) Keypair() *tls.Certificate {
	if k == nil {
		return nil
	}
	k.lock.RLock()
	defer k.lock.RUnlock()

	return k.tlsCert()
}

// CertAndKeyFiles returns cert and key files
func (k *KeypairReloader) CertAndKeyFiles() (string, string) {
	if k == nil {
		return "", ""
	}
	k.lock.RLock()
	defer k.lock.RUnlock()

	return k.certPath, k.keyPath
}

// LoadedAt return the last time when the pair was loaded
func (k *KeypairReloader) LoadedAt() time.Time {
	k.lock.RLock()
	defer k.lock.RUnlock()

	return k.loadedAt
}

// LoadedCount returns the number of times the pair was loaded from disk
func (k *KeypairReloader) LoadedCount() uint32 {
	return atomic.LoadUint32(&k.count)
}

// Close will close the reloader and release its resources
func (k *KeypairReloader) Close() error {
	if k == nil {
		return nil
	}

	k.lock.RLock()
	defer k.lock.RUnlock()

	if k.closed {
		return errors.New("already closed")
	}

	logger.Infof("label=%s, count=%d, cert=%q, key=%q", k.label, k.count, k.certPath, k.keyPath)

	k.closed = true
	k.stopChan <- struct{}{}

	return nil
}
