package revocation

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/gopkg", "revocation")

var (
	// TimeNowFn to override in unit tests
	TimeNowFn = time.Now
)

// snapshotTTL is how long a Redis scan of revoked token IDs is reused.
const snapshotTTL = 5 * time.Minute

// provider is a process-local cache of revoked token IDs in front of Redis.
//
// Validate runs on every authenticated request and Revoke runs alongside it.
// The snapshot is published by replacing the map. Writing an entry into the
// live map crashes the process with a concurrent map read and map write.
type provider struct {
	jwt.Revocation

	cache cache.Provider

	mu sync.RWMutex
	// revoked is the published snapshot. Replace the map; do not update it in place.
	revoked map[string]bool
	// local is the set of IDs revoked on this pod. A reload merges it so a
	// Redis scan that started before the revoke was stored cannot drop it.
	local    map[string]struct{}
	loadedAt time.Time
	// inflight is the shared reload. Concurrent Validates wait for it
	// instead of each running a Redis KEYS scan.
	inflight *reloadCall
}

// reloadCall is one in-flight Redis scan shared by every caller that
// arrived while the snapshot was stale.
type reloadCall struct {
	wg  sync.WaitGroup
	err error
}

func New(cache cache.Provider) jwt.Revocation {
	p := &provider{cache: cache}
	// TODO: pubsub?
	// sub := cache.Subscribe(context.Background(), "revoked")
	return p
}

// snapshotFresh reports whether the published snapshot is still inside snapshotTTL.
// Caller must hold p.mu.
func (p *provider) snapshotFresh() bool {
	return p.revoked != nil && !p.loadedAt.IsZero() && TimeNowFn().Sub(p.loadedAt) < snapshotTTL
}

func (p *provider) load(ctx context.Context) error {
	p.mu.RLock()
	fresh := p.snapshotFresh()
	p.mu.RUnlock()
	if fresh {
		return nil
	}

	p.mu.Lock()
	if p.snapshotFresh() {
		p.mu.Unlock()
		return nil
	}
	if call := p.inflight; call != nil {
		p.mu.Unlock()
		call.wg.Wait()
		return call.err
	}
	call := &reloadCall{}
	call.wg.Add(1)
	p.inflight = call
	p.mu.Unlock()

	err := p.reload(ctx)

	p.mu.Lock()
	p.inflight = nil
	p.mu.Unlock()
	// Publish the error before Done so waiters that wake on Wait observe it.
	call.err = err
	call.wg.Done()
	return err
}

func (p *provider) reload(ctx context.Context) error {
	keys, err := p.cache.Keys(ctx, "/revoked/*")
	if err != nil {
		return err
	}
	revoked := make(map[string]bool, len(keys))
	for _, key := range keys {
		idx := strings.LastIndex(key, "/")
		if idx < 0 {
			continue
		}
		revoked[key[idx+1:]] = true
	}

	p.mu.Lock()
	for id := range p.local {
		if revoked[id] {
			// Present in this scan, so a later one will see it too.
			delete(p.local, id)
			continue
		}
		revoked[id] = true
	}
	p.revoked = revoked
	p.loadedAt = TimeNowFn()
	p.mu.Unlock()

	logger.ContextKV(ctx, xlog.DEBUG, "loaded", len(revoked))
	return nil
}

func (p *provider) Validate(ctx context.Context, token string, claims jwt.MapClaims) error {
	if err := p.load(ctx); err != nil {
		return err
	}

	exp := claims.TimeVal("exp")
	now := TimeNowFn()
	if !exp.IsZero() && exp.Before(now) {
		return errors.Errorf("token expired at: %s, now: %s",
			exp.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}

	_, id := cacheKey(token, claims)
	p.mu.RLock()
	revoked := p.revoked[id]
	p.mu.RUnlock()
	if revoked {
		return errors.New("token revoked")
	}

	return nil
}

func (p *provider) Revoke(ctx context.Context, token string, claims jwt.MapClaims) error {
	exp := claims.TimeVal("exp")
	now := TimeNowFn()
	if exp.IsZero() {
		exp = now.Add(24 * time.Hour)
	} else if exp.Before(now) {
		// already expired
		return nil
	}

	key, id := cacheKey(token, claims)
	err := p.cache.Set(ctx, key, exp.Format(time.RFC3339), exp.Sub(now))
	if err != nil {
		return errors.WithMessage(err, "failed to revoke")
	}

	p.remember(id)
	return nil
}

// remember records an ID this pod has stored in Redis.
// The snapshot is swapped for a new map so readers never observe an in-place write.
func (p *provider) remember(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.local == nil {
		p.local = make(map[string]struct{})
	}
	p.local[id] = struct{}{}

	next := make(map[string]bool, len(p.revoked)+1)
	for existing := range p.revoked {
		next[existing] = true
	}
	next[id] = true
	p.revoked = next
}

func cacheKey(token string, claims jwt.MapClaims) (string, string) {
	id := claims.String("jti")
	if id == "" {
		id = certutil.SHA1Base64([]byte(token))
	}
	return fmt.Sprintf("/revoked/%s/%s", claims.String("sub"), id), id
}
