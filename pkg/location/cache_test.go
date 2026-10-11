package location_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/location"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errLookup is the error the fake providers fail with.
var errLookup = errors.New("lookup failed")

// fakeProvider answers with the place its answer func returns and records
// every address it was asked for.
type fakeProvider struct {
	answer func(ctx context.Context, addr netip.Addr) (*location.Place, error)

	mu    sync.Mutex
	asked []netip.Addr
}

func (p *fakeProvider) Location(ctx context.Context, addr netip.Addr) (*location.Place, error) {
	p.mu.Lock()
	p.asked = append(p.asked, addr)
	p.mu.Unlock()
	return p.answer(ctx, addr)
}

func (p *fakeProvider) calls() []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.Addr(nil), p.asked...)
}

// cityOf answers with the address as the city, so a test can tell which
// lookup an answer came from.
func cityOf(_ context.Context, addr netip.Addr) (*location.Place, error) {
	return &location.Place{City: addr.String()}, nil
}

func newCache(t *testing.T, p location.Provider, cfg location.CacheConfig) *location.Cache {
	t.Helper()
	c, err := location.NewCache(p, cfg)
	require.NoError(t, err)
	return c
}

// cityAt returns the city c reports for addr.
func cityAt(t *testing.T, c location.Provider, addr string) string {
	t.Helper()
	place, err := c.Location(context.Background(), netip.MustParseAddr(addr))
	require.NoError(t, err)
	require.NotNil(t, place)
	return place.City
}

func addrs(values ...string) []netip.Addr {
	ret := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		ret = append(ret, netip.MustParseAddr(v))
	}
	return ret
}

func TestNewCache(t *testing.T) {
	t.Parallel()

	p := &fakeProvider{answer: cityOf}
	tests := []struct {
		name     string
		provider location.Provider
		cfg      location.CacheConfig
		err      string
	}{
		{name: "defaults", provider: p, cfg: location.CacheConfig{Size: 1}},
		{
			name:     "custom",
			provider: p,
			cfg: location.CacheConfig{
				Size:     10,
				TTL:      location.NoExpiry,
				IPv4Bits: 32,
				IPv6Bits: 128,
			},
		},
		{name: "nil provider", cfg: location.CacheConfig{Size: 1}, err: "location provider is required"},
		{name: "zero size", provider: p, err: "invalid location cache size 0: must provide a positive size"},
		{name: "negative size", provider: p, cfg: location.CacheConfig{Size: -1}, err: "invalid location cache size -1: must provide a positive size"},
		{name: "ipv4 bits low", provider: p, cfg: location.CacheConfig{Size: 1, IPv4Bits: -1}, err: "invalid location cache IPv4 prefix length -1"},
		{name: "ipv4 bits high", provider: p, cfg: location.CacheConfig{Size: 1, IPv4Bits: 33}, err: "invalid location cache IPv4 prefix length 33"},
		{name: "ipv6 bits low", provider: p, cfg: location.CacheConfig{Size: 1, IPv6Bits: -1}, err: "invalid location cache IPv6 prefix length -1"},
		{name: "ipv6 bits high", provider: p, cfg: location.CacheConfig{Size: 1, IPv6Bits: 129}, err: "invalid location cache IPv6 prefix length 129"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := location.NewCache(tt.provider, tt.cfg)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				assert.Nil(t, c)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, c)
		})
	}
}

func TestCacheSharesNetwork(t *testing.T) {
	t.Parallel()

	p := &fakeProvider{answer: cityOf}
	c := newCache(t, p, location.CacheConfig{Size: 10})

	// IPv4: one answer per /24; a mapped address is looked up as IPv4
	assert.Equal(t, "8.8.8.8", cityAt(t, c, "::ffff:8.8.8.8"))
	assert.Equal(t, "8.8.8.8", cityAt(t, c, "8.8.8.200"))
	assert.Equal(t, "8.8.9.1", cityAt(t, c, "8.8.9.1"))
	// IPv6: one answer per /48, looked up without the zone
	assert.Equal(t, "2001:4860:4860::8888", cityAt(t, c, "2001:4860:4860::8888%eth0"))
	assert.Equal(t, "2001:4860:4860::8888", cityAt(t, c, "2001:4860:4860:ffff::1"))
	assert.Equal(t, "2001:4860:4861::1", cityAt(t, c, "2001:4860:4861::1"))

	assert.Equal(t, addrs("8.8.8.8", "8.8.9.1", "2001:4860:4860::8888", "2001:4860:4861::1"), p.calls())
}

func TestCachePrefixLengths(t *testing.T) {
	t.Parallel()

	p := &fakeProvider{answer: cityOf}
	c := newCache(t, p, location.CacheConfig{Size: 10, IPv4Bits: 16, IPv6Bits: 128})

	assert.Equal(t, "8.8.8.8", cityAt(t, c, "8.8.8.8"))
	assert.Equal(t, "8.8.8.8", cityAt(t, c, "8.8.200.1"))
	assert.Equal(t, "2001:4860::1", cityAt(t, c, "2001:4860::1"))
	assert.Equal(t, "2001:4860::2", cityAt(t, c, "2001:4860::2"))

	assert.Equal(t, addrs("8.8.8.8", "2001:4860::1", "2001:4860::2"), p.calls())
}

func TestCacheNotPublic(t *testing.T) {
	t.Parallel()

	p := &fakeProvider{answer: cityOf}
	c := newCache(t, p, location.CacheConfig{Size: 10})

	for _, addr := range []netip.Addr{{}, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::ffff:192.168.1.1"), netip.MustParseAddr("fe80::1%eth0")} {
		place, err := c.Location(context.Background(), addr)
		require.NoError(t, err)
		assert.Nil(t, place)
	}
	assert.Empty(t, p.calls())
}

func TestCacheKeepsNoLocation(t *testing.T) {
	t.Parallel()

	p := &fakeProvider{answer: func(context.Context, netip.Addr) (*location.Place, error) {
		return nil, nil
	}}
	c := newCache(t, p, location.CacheConfig{Size: 10})

	for range 2 {
		place, err := c.Location(context.Background(), netip.MustParseAddr("1.1.1.1"))
		require.NoError(t, err)
		assert.Nil(t, place)
	}
	assert.Equal(t, addrs("1.1.1.1"), p.calls())
}

func TestCacheRetriesErrors(t *testing.T) {
	t.Parallel()

	var failed atomic.Bool
	p := &fakeProvider{answer: func(ctx context.Context, addr netip.Addr) (*location.Place, error) {
		if failed.CompareAndSwap(false, true) {
			return nil, errors.WithStack(errLookup)
		}
		return cityOf(ctx, addr)
	}}
	c := newCache(t, p, location.CacheConfig{Size: 10})
	ctx := context.Background()

	place, err := c.Location(ctx, netip.MustParseAddr("1.1.1.1"))
	require.ErrorIs(t, err, errLookup)
	assert.Nil(t, place)

	// the failure was not kept: the next address of the network is looked up
	assert.Equal(t, "1.1.1.2", cityAt(t, c, "1.1.1.2"))
	assert.Equal(t, "1.1.1.2", cityAt(t, c, "1.1.1.3"))
	assert.Equal(t, addrs("1.1.1.1", "1.1.1.2"), p.calls())
}

func TestCacheReturnsCopies(t *testing.T) {
	t.Parallel()

	shared := &location.Place{City: "Lima", Country: "Peru"}
	p := &fakeProvider{answer: func(context.Context, netip.Addr) (*location.Place, error) {
		return shared, nil
	}}
	c := newCache(t, p, location.CacheConfig{Size: 10})
	ctx := context.Background()
	addr := netip.MustParseAddr("1.1.1.1")

	first, err := c.Location(ctx, addr)
	require.NoError(t, err)
	first.City = "changed by caller"
	shared.Country = "changed by provider"

	second, err := c.Location(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, &location.Place{City: "Lima", Country: "Peru"}, second)
	assert.NotSame(t, first, second)
	assert.Len(t, p.calls(), 1)
}

func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	t.Parallel()

	p := &fakeProvider{answer: cityOf}
	c := newCache(t, p, location.CacheConfig{Size: 2})

	assert.Equal(t, "1.1.1.1", cityAt(t, c, "1.1.1.1"))
	assert.Equal(t, "8.8.8.8", cityAt(t, c, "8.8.8.8"))
	assert.Equal(t, "1.1.1.1", cityAt(t, c, "1.1.1.9")) // 1.1.1.0/24 is now the most recent
	assert.Equal(t, "9.9.9.9", cityAt(t, c, "9.9.9.9")) // evicts 8.8.8.0/24
	assert.Equal(t, "1.1.1.1", cityAt(t, c, "1.1.1.1"))
	assert.Equal(t, "8.8.8.7", cityAt(t, c, "8.8.8.7"))

	assert.Equal(t, addrs("1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.8.7"), p.calls())
}

// TestCacheExpiredNotPromoted checks that an expired entry whose refresh
// fails stays the least recently used, so a live entry is not evicted first.
func TestCacheExpiredNotPromoted(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var failing atomic.Bool
		p := &fakeProvider{answer: func(ctx context.Context, addr netip.Addr) (*location.Place, error) {
			if failing.Load() {
				return nil, errors.WithStack(errLookup)
			}
			return cityOf(ctx, addr)
		}}
		c := newCache(t, p, location.CacheConfig{Size: 2, TTL: time.Hour})

		assert.Equal(t, "1.1.1.1", cityAt(t, c, "1.1.1.1"))
		time.Sleep(30 * time.Minute)
		assert.Equal(t, "8.8.8.8", cityAt(t, c, "8.8.8.8"))
		time.Sleep(31 * time.Minute) // 1.1.1.0/24 expired, 8.8.8.0/24 live

		failing.Store(true)
		_, err := c.Location(context.Background(), netip.MustParseAddr("1.1.1.1"))
		require.ErrorIs(t, err, errLookup)
		failing.Store(false)

		assert.Equal(t, "9.9.9.9", cityAt(t, c, "9.9.9.9")) // evicts 1.1.1.0/24
		assert.Equal(t, "8.8.8.8", cityAt(t, c, "8.8.8.9"))
		assert.Equal(t, addrs("1.1.1.1", "8.8.8.8", "1.1.1.1", "9.9.9.9"), p.calls())
	})
}

func TestCacheTTL(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		ttl     time.Duration
		expires time.Duration
	}{
		{name: "custom", ttl: time.Hour, expires: time.Hour},
		{name: "default", expires: location.DefaultCacheTTL},
		{name: "no expiry", ttl: location.NoExpiry},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				p := &fakeProvider{answer: cityOf}
				c := newCache(t, p, location.CacheConfig{Size: 10, TTL: tt.ttl})

				assert.Equal(t, "1.1.1.1", cityAt(t, c, "1.1.1.1"))
				if tt.expires == 0 {
					time.Sleep(10 * 365 * 24 * time.Hour)
					assert.Equal(t, "1.1.1.1", cityAt(t, c, "1.1.1.2"))
					assert.Len(t, p.calls(), 1)
					return
				}
				time.Sleep(tt.expires - time.Nanosecond)
				assert.Equal(t, "1.1.1.1", cityAt(t, c, "1.1.1.2"))
				time.Sleep(time.Nanosecond)
				assert.Equal(t, "1.1.1.3", cityAt(t, c, "1.1.1.3"))
				assert.Equal(t, "1.1.1.3", cityAt(t, c, "1.1.1.4"))
				assert.Equal(t, addrs("1.1.1.1", "1.1.1.3"), p.calls())
			})
		})
	}
}

// blockingProvider holds every lookup until release is closed.
func blockingProvider(release <-chan struct{}, answer func(context.Context, netip.Addr) (*location.Place, error)) *fakeProvider {
	return &fakeProvider{answer: func(ctx context.Context, addr netip.Addr) (*location.Place, error) {
		<-release
		return answer(ctx, addr)
	}}
}

type result struct {
	place *location.Place
	err   error
}

// startLookups starts n lookups of addr and returns their results channel.
func startLookups(ctx context.Context, c location.Provider, addr string, n int) <-chan result {
	results := make(chan result, n)
	for range n {
		go func() {
			place, err := c.Location(ctx, netip.MustParseAddr(addr))
			results <- result{place: place, err: err}
		}()
	}
	return results
}

func TestCacheSharesLookup(t *testing.T) {
	t.Parallel()

	t.Run("place", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			p := blockingProvider(release, cityOf)
			c := newCache(t, p, location.CacheConfig{Size: 10})

			first := startLookups(t.Context(), c, "8.8.8.8", 1)
			synctest.Wait()
			waiters := startLookups(t.Context(), c, "8.8.8.9", 4)
			synctest.Wait()
			close(release)

			assert.Equal(t, result{place: &location.Place{City: "8.8.8.8"}}, <-first)
			var places []*location.Place
			for range 4 {
				r := <-waiters
				require.NoError(t, r.err)
				assert.Equal(t, &location.Place{City: "8.8.8.8"}, r.place)
				places = append(places, r.place)
			}
			assert.NotSame(t, places[0], places[1])
			assert.Equal(t, addrs("8.8.8.8"), p.calls())
		})
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			p := blockingProvider(release, func(context.Context, netip.Addr) (*location.Place, error) {
				return nil, errors.WithStack(errLookup)
			})
			c := newCache(t, p, location.CacheConfig{Size: 10})

			results := startLookups(t.Context(), c, "8.8.8.8", 3)
			synctest.Wait()
			close(release)
			for range 3 {
				r := <-results
				require.ErrorIs(t, r.err, errLookup)
				assert.Nil(t, r.place)
			}
			assert.Len(t, p.calls(), 1)
		})
	})

	t.Run("waiter context", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			p := blockingProvider(release, cityOf)
			c := newCache(t, p, location.CacheConfig{Size: 10})

			first := startLookups(t.Context(), c, "8.8.8.8", 1)
			synctest.Wait()
			ctx, cancel := context.WithCancel(t.Context())
			waiter := startLookups(ctx, c, "8.8.8.9", 1)
			synctest.Wait()
			cancel()

			r := <-waiter
			require.ErrorIs(t, r.err, context.Canceled)
			assert.Nil(t, r.place)

			close(release)
			assert.Equal(t, result{place: &location.Place{City: "8.8.8.8"}}, <-first)
			assert.Len(t, p.calls(), 1)
		})
	})

	t.Run("first caller gives up", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			p := &fakeProvider{answer: func(ctx context.Context, addr netip.Addr) (*location.Place, error) {
				select {
				case <-release:
					return cityOf(ctx, addr)
				case <-ctx.Done():
					return nil, errors.WithStack(ctx.Err())
				}
			}}
			c := newCache(t, p, location.CacheConfig{Size: 10})

			ctx, cancel := context.WithCancel(t.Context())
			first := startLookups(ctx, c, "8.8.8.8", 1)
			synctest.Wait()
			waiters := startLookups(t.Context(), c, "8.8.8.9", 2)
			synctest.Wait()
			cancel()

			r := <-first
			require.ErrorIs(t, r.err, context.Canceled)
			assert.Nil(t, r.place)

			// the waiters, whose ctx is live, look the network up again, once
			synctest.Wait()
			close(release)
			for range 2 {
				assert.Equal(t, result{place: &location.Place{City: "8.8.8.9"}}, <-waiters)
			}
			assert.Equal(t, addrs("8.8.8.8", "8.8.8.9"), p.calls())
		})
	})

	t.Run("genuine error after first caller gave up", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			// the provider ignores ctx and fails on its own
			p := blockingProvider(release, func(context.Context, netip.Addr) (*location.Place, error) {
				return nil, errors.WithStack(errLookup)
			})
			c := newCache(t, p, location.CacheConfig{Size: 10})

			ctx, cancel := context.WithCancel(t.Context())
			first := startLookups(ctx, c, "8.8.8.8", 1)
			synctest.Wait()
			waiters := startLookups(t.Context(), c, "8.8.8.9", 3)
			synctest.Wait()
			cancel()
			close(release)

			// the failure is about the address, so the waiters share it
			for range 4 {
				var r result
				select {
				case r = <-first:
				case r = <-waiters:
				}
				require.ErrorIs(t, r.err, errLookup)
				assert.Nil(t, r.place)
			}
			assert.Len(t, p.calls(), 1)
		})
	})

	t.Run("provider panic", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			var panicked atomic.Bool
			p := blockingProvider(release, func(ctx context.Context, addr netip.Addr) (*location.Place, error) {
				if panicked.CompareAndSwap(false, true) {
					panic("provider bug")
				}
				return cityOf(ctx, addr)
			})
			c := newCache(t, p, location.CacheConfig{Size: 10})

			recovered := make(chan any, 1)
			go func() {
				defer func() { recovered <- recover() }()
				_, _ = c.Location(t.Context(), netip.MustParseAddr("8.8.8.8"))
			}()
			synctest.Wait()
			waiter := startLookups(t.Context(), c, "8.8.8.9", 1)
			synctest.Wait()
			close(release)

			assert.Equal(t, "provider bug", <-recovered)
			r := <-waiter
			require.EqualError(t, r.err, "location lookup of 8.8.8.8 did not complete")
			assert.Nil(t, r.place)

			// the failed lookup left nothing behind
			assert.Equal(t, "8.8.8.10", cityAt(t, c, "8.8.8.10"))
			assert.Equal(t, addrs("8.8.8.8", "8.8.8.10"), p.calls())
		})
	})
}

// TestCacheConcurrent races lookups of a few networks through a cache too
// small to hold them; run it with -race.
func TestCacheConcurrent(t *testing.T) {
	t.Parallel()

	var lookups atomic.Int32
	p := &fakeProvider{answer: func(_ context.Context, addr netip.Addr) (*location.Place, error) {
		lookups.Add(1)
		prefix, err := addr.Prefix(24)
		if err != nil {
			return nil, err
		}
		return &location.Place{City: prefix.String()}, nil
	}}
	c := newCache(t, p, location.CacheConfig{Size: 3})

	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			for i := range 200 {
				network := (g + i) % 6
				addr := netip.MustParseAddr(fmt.Sprintf("8.8.%d.%d", network, i%250+1))
				place, err := c.Location(context.Background(), addr)
				if !assert.NoError(t, err) || !assert.NotNil(t, place) {
					return
				}
				assert.Equal(t, fmt.Sprintf("8.8.%d.0/24", network), place.City)
			}
		})
	}
	wg.Wait()
	assert.GreaterOrEqual(t, lookups.Load(), int32(6))
	assert.Less(t, lookups.Load(), int32(16*200))
}
