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

func TestReloadPages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := cache.NewMemoryProvider("test")

	// revoked by another process: only a reload that follows the cursor
	// past the first page finds every ID
	const n = 2*reloadPageSize + 1
	exp := time.Now().Add(time.Hour)
	for i := range n {
		key, _ := cacheKey("token", claimsFor(strconv.Itoa(i)))
		require.NoError(t, mem.Set(ctx, key, exp.Format(time.RFC3339), time.Hour))
	}

	store := &gatingCache{Provider: mem}
	p := New(store)
	for i := range n {
		assert.EqualError(t, p.Validate(ctx, "token", claimsFor(strconv.Itoa(i))), "token revoked", i)
	}
	assert.NoError(t, p.Validate(ctx, "token", claimsFor("other")))
	assert.Equal(t, 1, store.callCount())
	assert.Equal(t, 3, store.pageCount())
}

func TestReloadPageErrorKeepsSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := cache.NewMemoryProvider("test")

	// two pages, so the second can fail after the first succeeded
	const n = reloadPageSize + 1
	exp := time.Now().Add(time.Hour)
	for i := range n {
		key, _ := cacheKey("token", claimsFor(strconv.Itoa(i)))
		require.NoError(t, mem.Set(ctx, key, exp.Format(time.RFC3339), time.Hour))
	}

	store := &gatingCache{Provider: mem}
	p := New(store)
	require.EqualError(t, p.Validate(ctx, "token", claimsFor("0")), "token revoked")
	ageSnapshot(p)
	prov := p.(*provider)
	prov.mu.RLock()
	published, loadedAt := prov.revoked, prov.loadedAt
	prov.mu.RUnlock()
	require.Len(t, published, n)

	// a failed later page fails the reload: nothing of the first page is
	// published and the stale snapshot stays as it was
	store.setPageErr(errors.New("redis down"))
	assert.EqualError(t, p.Validate(ctx, "token", claimsFor("0")), "redis down")
	prov.mu.RLock()
	assert.Equal(t, loadedAt, prov.loadedAt)
	assert.Equal(t, published, prov.revoked)
	prov.mu.RUnlock()
	assert.Equal(t, 2, store.callCount())

	// the next Validate scans again
	store.setPageErr(nil)
	assert.EqualError(t, p.Validate(ctx, "token", claimsFor("0")), "token revoked")
	assert.Equal(t, 3, store.callCount())
	assert.Equal(t, 6, store.pageCount())
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

// gatingCache counts the scans (ListKeys calls from an empty cursor) and the
// pages, can hold the first page of a scan open so tests can revoke while
// that scan is in flight, and can fail the pages after the first.
type gatingCache struct {
	cache.Provider
	mu    sync.Mutex
	calls int
	pages int
	gate  *keyGate
	// pageErr is returned for every page after the first.
	pageErr error
}

type keyGate struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
	err     error
	// freeze returns the page captured when the scan began, so a revoke
	// stored while the scan is blocked is absent from the result.
	freeze bool
}

func (g *gatingCache) setGate(gate *keyGate) {
	g.mu.Lock()
	g.gate = gate
	g.mu.Unlock()
}

func (g *gatingCache) setPageErr(err error) {
	g.mu.Lock()
	g.pageErr = err
	g.mu.Unlock()
}

func (g *gatingCache) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

func (g *gatingCache) pageCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pages
}

func (g *gatingCache) ListKeys(ctx context.Context, pattern, cursor string, count int) ([]string, string, error) {
	g.mu.Lock()
	g.pages++
	var gate *keyGate
	if cursor == "" {
		g.calls++
		gate = g.gate
	}
	pageErr := g.pageErr
	g.mu.Unlock()
	if cursor != "" && pageErr != nil {
		return nil, "", pageErr
	}
	if gate == nil {
		return g.Provider.ListKeys(ctx, pattern, cursor, count)
	}

	var (
		keys []string
		next string
		err  error
	)
	if gate.freeze {
		keys, next, err = g.Provider.ListKeys(ctx, pattern, cursor, count)
		if err != nil {
			return nil, "", err
		}
	}
	gate.once.Do(func() { close(gate.started) })
	<-gate.release
	if gate.err != nil {
		return nil, "", gate.err
	}
	if gate.freeze {
		return keys, next, nil
	}
	return g.Provider.ListKeys(ctx, pattern, cursor, count)
}
