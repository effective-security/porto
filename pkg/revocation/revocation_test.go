package revocation

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevocation(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemoryProvider("test")

	p := New(c)
	assert.NoError(t, p.Validate(ctx, "token", jwt.MapClaims{"sub": "user", "exp": time.Now().Add(time.Hour).Unix()}))

	cl := jwt.MapClaims{"sub": "user", "jti": "11111", "exp": time.Now().Add(time.Hour).Unix()}
	assert.NoError(t, p.Validate(ctx, "token", cl))

	require.NoError(t, p.Revoke(ctx, "token", cl))
	assert.EqualError(t, p.Validate(ctx, "token", cl), "token revoked")

	cl = jwt.MapClaims{"sub": "user", "jti": "11111", "exp": time.Now().Add(-time.Second).Unix()}
	err := p.Validate(ctx, "token", cl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired at:")
	// revoke already expired
	require.NoError(t, p.Revoke(ctx, "token", cl))
	err = p.Validate(ctx, "token", cl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired at:")

	// no expiration
	cl = jwt.MapClaims{"sub": "user", "jti": "11111"}
	assert.EqualError(t, p.Validate(ctx, "token", cl), "token revoked")

	cl = jwt.MapClaims{"sub": "user", "jti": "11112"}
	err = p.Validate(ctx, "token", cl)
	require.NoError(t, err)
	require.NoError(t, p.Revoke(ctx, "token", cl))
	assert.EqualError(t, p.Validate(ctx, "token", cl), "token revoked")
}

func TestRevokeReplacesSnapshot(t *testing.T) {
	ctx := context.Background()
	p := New(cache.NewMemoryProvider("test"))
	prov := p.(*provider)

	first := jwt.MapClaims{"sub": "user", "jti": "first", "exp": time.Now().Add(time.Hour).Unix()}
	require.NoError(t, p.Revoke(ctx, "token", first))

	prov.mu.RLock()
	published := prov.revoked
	prov.mu.RUnlock()

	second := jwt.MapClaims{"sub": "user", "jti": "second", "exp": time.Now().Add(time.Hour).Unix()}
	require.NoError(t, p.Revoke(ctx, "token", second))

	prov.mu.RLock()
	defer prov.mu.RUnlock()
	assert.True(t, published["first"])
	_, overwritten := published["second"]
	assert.False(t, overwritten)
	assert.True(t, prov.revoked["first"])
	assert.True(t, prov.revoked["second"])
}

func TestConcurrentValidateAndRevoke(t *testing.T) {
	ctx := context.Background()
	p := New(cache.NewMemoryProvider("test"))

	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			cl := jwt.MapClaims{
				"sub": "user",
				"jti": strconv.Itoa(i),
				"exp": time.Now().Add(time.Hour).Unix(),
			}
			if err := p.Revoke(ctx, "token", cl); err != nil {
				t.Errorf("revoke %d: %v", i, err)
			}
			_ = p.Validate(ctx, "token", cl)
		}()
	}
	wg.Wait()

	for i := range n {
		cl := jwt.MapClaims{
			"sub": "user",
			"jti": strconv.Itoa(i),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		assert.EqualError(t, p.Validate(ctx, "token", cl), "token revoked")
	}
}

func TestReloadKeepsRevokeStartedBeforeStore(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		mem := cache.NewMemoryProvider("test")
		gate := &keyGate{started: make(chan struct{}), release: make(chan struct{}), freeze: true}
		store := &gatingCache{Provider: mem}
		p := New(store)

		kept := claimsFor("kept")
		require.NoError(t, p.Revoke(ctx, "token", kept))
		require.EqualError(t, p.Validate(ctx, "token", kept), "token revoked")
		ageSnapshot(p)

		store.setGate(gate)
		missed := claimsFor("missed")
		done := make(chan error, 1)
		go func() {
			done <- p.Validate(ctx, "token", missed)
		}()
		<-gate.started

		// The scan already captured keys, and this revoke is not among them.
		require.NoError(t, p.Revoke(ctx, "token", missed))
		close(gate.release)

		require.EqualError(t, <-done, "token revoked")
		assert.EqualError(t, p.Validate(ctx, "token", kept), "token revoked")
		assert.EqualError(t, p.Validate(ctx, "token", missed), "token revoked")
		assert.Equal(t, 2, store.callCount())

		prov := p.(*provider)
		prov.mu.RLock()
		_, keptLocal := prov.local["kept"]
		_, missedLocal := prov.local["missed"]
		prov.mu.RUnlock()
		assert.False(t, keptLocal)
		assert.True(t, missedLocal)

		// The next scan sees the revoke in Redis and can drop the local copy.
		store.setGate(nil)
		ageSnapshot(p)
		assert.EqualError(t, p.Validate(ctx, "token", missed), "token revoked")
		prov.mu.RLock()
		assert.Empty(t, prov.local)
		prov.mu.RUnlock()
		assert.Equal(t, 3, store.callCount())
	})
}

func TestConcurrentValidateSharesReload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		store := &gatingCache{Provider: cache.NewMemoryProvider("test")}
		p := New(store)
		require.NoError(t, p.Validate(ctx, "token", claimsFor("user")))
		ageSnapshot(p)

		gate := &keyGate{started: make(chan struct{}), release: make(chan struct{})}
		store.setGate(gate)
		before := store.callCount()

		const n = 8
		errs := make([]error, n)
		var wg sync.WaitGroup
		wg.Add(n)
		for i := range n {
			go func() {
				defer wg.Done()
				errs[i] = p.Validate(ctx, "token", claimsFor("user"))
			}()
		}
		synctest.Wait()
		assert.Equal(t, before+1, store.callCount())

		close(gate.release)
		wg.Wait()
		for _, err := range errs {
			assert.NoError(t, err)
		}
		assert.Equal(t, before+1, store.callCount())
	})
}

func TestReloadErrorIsSharedAndRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		store := &gatingCache{Provider: cache.NewMemoryProvider("test")}
		p := New(store)
		require.NoError(t, p.Validate(ctx, "token", claimsFor("user")))
		ageSnapshot(p)

		gate := &keyGate{
			started: make(chan struct{}),
			release: make(chan struct{}),
			err:     errors.New("redis down"),
		}
		store.setGate(gate)
		before := store.callCount()

		const n = 8
		errs := make([]error, n)
		var wg sync.WaitGroup
		wg.Add(n)
		for i := range n {
			go func() {
				defer wg.Done()
				errs[i] = p.Validate(ctx, "token", claimsFor("user"))
			}()
		}
		synctest.Wait()
		assert.Equal(t, before+1, store.callCount())

		close(gate.release)
		wg.Wait()
		for _, err := range errs {
			assert.EqualError(t, err, "redis down")
		}
		assert.Equal(t, before+1, store.callCount())

		// A later request tries again instead of pinning the outage for the whole TTL.
		store.setGate(nil)
		assert.NoError(t, p.Validate(ctx, "token", claimsFor("user")))
		assert.Equal(t, before+2, store.callCount())
	})
}

func claimsFor(jti string) jwt.MapClaims {
	return jwt.MapClaims{"sub": "user", "jti": jti, "exp": time.Now().Add(time.Hour).Unix()}
}

func ageSnapshot(p jwt.Revocation) {
	prov := p.(*provider)
	prov.mu.Lock()
	prov.loadedAt = TimeNowFn().Add(-snapshotTTL - time.Second)
	prov.mu.Unlock()
}

// gatingCache counts Keys calls and can hold a scan open so tests can
// revoke while that scan is in flight.
type gatingCache struct {
	cache.Provider
	mu    sync.Mutex
	calls int
	gate  *keyGate
}

type keyGate struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
	err     error
	// freeze returns the key list captured when Keys began, so a revoke
	// stored while the scan is blocked is absent from the result.
	freeze bool
}

func (g *gatingCache) setGate(gate *keyGate) {
	g.mu.Lock()
	g.gate = gate
	g.mu.Unlock()
}

func (g *gatingCache) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

func (g *gatingCache) Keys(ctx context.Context, pattern string) ([]string, error) {
	g.mu.Lock()
	g.calls++
	gate := g.gate
	g.mu.Unlock()
	if gate == nil {
		return g.Provider.Keys(ctx, pattern)
	}

	var keys []string
	var err error
	if gate.freeze {
		keys, err = g.Provider.Keys(ctx, pattern)
		if err != nil {
			return nil, err
		}
	}
	gate.once.Do(func() { close(gate.started) })
	<-gate.release
	if gate.err != nil {
		return nil, gate.err
	}
	if gate.freeze {
		return keys, nil
	}
	return g.Provider.Keys(ctx, pattern)
}
