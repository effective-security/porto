package location

import (
	"cmp"
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	// DefaultCacheTTL is how long Cache keeps an answer when
	// CacheConfig.TTL is zero.
	DefaultCacheTTL = 24 * time.Hour
	// NoExpiry as CacheConfig.TTL keeps answers until they are evicted.
	NoExpiry time.Duration = -1
	// DefaultIPv4Bits is the IPv4 prefix length that shares one answer when
	// CacheConfig.IPv4Bits is zero: a /24 network.
	DefaultIPv4Bits = 24
	// DefaultIPv6Bits is the IPv6 prefix length that shares one answer when
	// CacheConfig.IPv6Bits is zero: a /48 site.
	DefaultIPv6Bits = 48
)

// CacheConfig configures NewCache.
type CacheConfig struct {
	// Size is the number of networks whose answers are kept; the least
	// recently used one is evicted first. Required.
	Size int `json:"size,omitempty" yaml:"size,omitempty"`
	// TTL is how long an answer is kept. Zero means DefaultCacheTTL and
	// NoExpiry (any negative value) keeps answers until they are evicted.
	TTL time.Duration `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// IPv4Bits is the prefix length of the IPv4 networks whose addresses
	// share one answer, 1 to 32. Default DefaultIPv4Bits.
	IPv4Bits int `json:"ipv4_bits,omitempty" yaml:"ipv4_bits,omitempty"`
	// IPv6Bits is the prefix length of the IPv6 networks whose addresses
	// share one answer, 1 to 128. Default DefaultIPv6Bits.
	IPv6Bits int `json:"ipv6_bits,omitempty" yaml:"ipv6_bits,omitempty"`
}

// Cache is a Provider that remembers the answers of another Provider per
// network: every address of an IPv4 /24 or an IPv6 /48 (by default) gets
// the answer looked up for the first one. It keeps places and "no location"
// answers, but not errors, so a failed lookup is retried on the next call.
// Concurrent calls for the same network share one lookup. Cache is safe for
// concurrent use and starts no goroutines.
type Cache struct {
	provider Provider
	ttl      time.Duration
	ipv4Bits int
	ipv6Bits int
	// entries locks itself (lru.Cache, unlike simplelru.LRU); mu guards
	// only inflight.
	entries *lru.Cache[netip.Prefix, cacheEntry]

	mu       sync.Mutex
	inflight map[netip.Prefix]*lookup
}

// cacheEntry is a remembered answer; place is nil for "no location" and a
// zero expires never expires.
type cacheEntry struct {
	place   *Place
	expires time.Time
}

// lookup is a Provider call in progress; done is closed once place, err and
// canceled are set. canceled reports that the call failed with a ctx error
// after the ctx of the caller that ran it was done, so its error says
// nothing about the address.
type lookup struct {
	done     chan struct{}
	place    *Place
	err      error
	canceled bool
}

// NewCache returns a Cache over provider. It returns an error when provider
// is nil, cfg.Size is not positive, or a prefix length is out of range.
func NewCache(provider Provider, cfg CacheConfig) (*Cache, error) {
	if provider == nil {
		return nil, errors.New("location provider is required")
	}
	ipv4Bits := cmp.Or(cfg.IPv4Bits, DefaultIPv4Bits)
	if ipv4Bits < 1 || ipv4Bits > 32 {
		return nil, errors.Errorf("invalid location cache IPv4 prefix length %d", cfg.IPv4Bits)
	}
	ipv6Bits := cmp.Or(cfg.IPv6Bits, DefaultIPv6Bits)
	if ipv6Bits < 1 || ipv6Bits > 128 {
		return nil, errors.Errorf("invalid location cache IPv6 prefix length %d", cfg.IPv6Bits)
	}
	entries, err := lru.New[netip.Prefix, cacheEntry](cfg.Size)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid location cache size %d", cfg.Size)
	}
	return &Cache{
		provider: provider,
		ttl:      cmp.Or(cfg.TTL, DefaultCacheTTL),
		ipv4Bits: ipv4Bits,
		ipv6Bits: ipv6Bits,
		entries:  entries,
		inflight: make(map[netip.Prefix]*lookup),
	}, nil
}

// Location implements Provider. Addresses that are not public return nil
// without a lookup and are not cached. A miss asks the wrapped Provider with
// ctx and addr, so ctx must allow for the provider's latency: a lookup cut
// short by ctx is an error and is not cached. Callers that arrive while that
// lookup runs wait for it, or for their own ctx, and share its result. When
// that lookup failed because its caller's ctx was done, a waiter whose ctx
// is not done looks the address up again instead. Each call returns its own
// copy of the Place.
func (c *Cache) Location(ctx context.Context, addr netip.Addr) (*Place, error) {
	if !IsPublic(addr) {
		return nil, nil
	}
	addr = canonical(addr)
	key := c.key(addr)
	for {
		if place, ok := c.get(key); ok {
			return place.clone(), nil
		}

		c.mu.Lock()
		l := c.inflight[key]
		if l == nil {
			// The lookup that just finished stored its answer before it
			// left inflight; check again so this call does not repeat it.
			if place, ok := c.get(key); ok {
				c.mu.Unlock()
				return place.clone(), nil
			}
			l = &lookup{done: make(chan struct{})}
			c.inflight[key] = l
			c.mu.Unlock()

			c.resolve(ctx, key, addr, l)
			return l.place.clone(), l.err
		}
		c.mu.Unlock()

		select {
		case <-l.done:
		case <-ctx.Done():
			return nil, errors.WithStack(ctx.Err())
		}
		if !l.canceled {
			return l.place.clone(), l.err
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.WithStack(err)
		}
	}
}

// resolve runs the lookup l for addr and stores a successful answer under
// key. It always releases the callers waiting on l, also when the Provider
// panics.
func (c *Cache) resolve(ctx context.Context, key netip.Prefix, addr netip.Addr, l *lookup) {
	completed := false
	defer func() {
		if !completed {
			l.err = errors.Errorf("location lookup of %s did not complete", addr)
		}
		c.mu.Lock()
		delete(c.inflight, key)
		c.mu.Unlock()
		close(l.done)
	}()

	place, err := c.provider.Location(ctx, addr)
	completed = true
	if err == nil {
		entry := cacheEntry{place: place.clone()}
		if c.ttl > 0 {
			entry.expires = time.Now().Add(c.ttl)
		}
		c.entries.Add(key, entry)
	}
	l.place, l.err = place, err
	l.canceled = ctx.Err() != nil &&
		(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
}

// key returns the network of addr that shares one answer.
func (c *Cache) key(addr netip.Addr) netip.Prefix {
	bits := c.ipv6Bits
	if addr.Is4() {
		bits = c.ipv4Bits
	}
	// bits is within range for the family, so Prefix cannot fail.
	prefix, _ := addr.Prefix(bits)
	return prefix
}

// get returns the remembered answer for key, if any and not expired. Only
// a live entry becomes the most recently used, so an expired one whose
// refresh fails is evicted before live ones.
func (c *Cache) get(key netip.Prefix) (*Place, bool) {
	entry, ok := c.entries.Peek(key)
	if !ok || (!entry.expires.IsZero() && !time.Now().Before(entry.expires)) {
		return nil, false
	}
	c.entries.Get(key)
	return entry.place, true
}
