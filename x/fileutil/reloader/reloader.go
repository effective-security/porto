package reloader

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/x/fileutil", "reloader")

// Wrap time.Tick so we can override it in tests.
var makeTicker = func(interval time.Duration) (func(), <-chan time.Time) {
	t := time.NewTicker(interval)
	return t.Stop, t.C
}

// OnChangedFunc is a called when the file has been modified
type OnChangedFunc func(filePath string, modifiedAt time.Time)

// Reloader keeps necessary info to provide reloaded certificate
type Reloader struct {
	lock           sync.RWMutex
	loadedAt       time.Time
	count          uint32
	filePath       string
	fileModifiedAt time.Time
	onChangedFunc  OnChangedFunc
	inProgress     bool
	stopChan       chan<- struct{}
	closed         bool
}

// NewReloader return an instance of the file re-loader
func NewReloader(filePath string, checkInterval time.Duration, onChangedFunc OnChangedFunc) (*Reloader, error) {
	result := &Reloader{
		filePath:      filePath,
		onChangedFunc: onChangedFunc,
		stopChan:      make(chan struct{}),
	}

	logger.Infof("status=started, file=%q", filePath)

	stopChan := make(chan struct{})
	result.stopChan = stopChan
	tickerStop, tickChan := makeTicker(checkInterval)
	go func() {
		for {
			select {
			case <-stopChan:
				tickerStop()
				logger.Infof("status=closed, count=%d, file=%q",
					result.LoadedCount(), filePath)
				return
			case <-tickChan:
				modified := false
				fi, err := os.Stat(filePath)
				if err == nil {
					modified = fi.ModTime().After(result.fileModifiedAt)
					if modified {
						result.fileModifiedAt = fi.ModTime()
						err := result.Reload()
						if err != nil {
							logger.Errorf("err=[%+v]", err)
						}
					}
				} else {
					logger.Warningf("reason=stat, file=%q, err=[%v]", filePath, err)
				}
			}
		}
	}()
	return result, nil
}

// Reload will explicitly call the callback function
func (k *Reloader) Reload() error {
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

	atomic.AddUint32(&k.count, 1)
	k.loadedAt = time.Now().UTC()

	go k.onChangedFunc(k.filePath, k.fileModifiedAt)

	return nil
}

// LoadedAt return the last time when the pair was loaded
func (k *Reloader) LoadedAt() time.Time {
	k.lock.RLock()
	defer k.lock.RUnlock()

	return k.loadedAt
}

// LoadedCount returns the number of times the pair was loaded from disk
func (k *Reloader) LoadedCount() uint32 {
	return atomic.LoadUint32(&k.count)
}

// Close will close the reloader and release its resources
func (k *Reloader) Close() error {
	if k == nil {
		return nil
	}

	k.lock.RLock()
	defer k.lock.RUnlock()

	if k.closed {
		return errors.New("already closed")
	}

	k.closed = true
	k.stopChan <- struct{}{}

	return nil
}
