package cache

import (
	"cmp"
	"container/heap"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

type memProv struct {
	ns namespace

	// mu guards subs and closed, so that Subscribe cannot register a
	// subscription that a concurrent Close would miss; Publish holds it for
	// reading while it delivers.
	mu     sync.RWMutex
	subs   map[*msub]struct{}
	closed bool

	cache sync.Map
}

type entry struct {
	expires *time.Time
	// keep JSON encoded to be in parity with Redis
	data []byte
}

// live reports whether e has not expired at now.
func (e *entry) live(now time.Time) bool {
	return e.expires == nil || e.expires.After(now)
}

// NewMemoryProvider returns an in-process Provider whose keys are stored
// under prefix like the Redis provider's (an empty prefix becomes "/").
// Values are kept JSON encoded; the store is unbounded and expired entries
// are only dropped on Get or CleanExpired.
func NewMemoryProvider(prefix string) Provider {
	prov := &memProv{
		ns:   newNamespace(cmp.Or(prefix, "/")),
		subs: make(map[*msub]struct{}),
	}

	return prov
}

// Close closes every live subscription, so a pending ReceiveMessage
// returns ErrClosed, and a later Subscribe returns a failed subscription
// reporting ErrClosed; the in-process store itself stays usable.
// It is rare to Close a Client, as the Client is meant to be long-lived and shared between many goroutines.
func (p *memProv) Close() error {
	p.mu.Lock()
	p.closed = true
	subs := slices.Collect(maps.Keys(p.subs))
	p.subs = nil
	p.mu.Unlock()

	for _, s := range subs {
		_ = s.Close() // never fails
	}
	return nil
}

// IsLocal returns true, if cache is local
func (p *memProv) IsLocal() bool {
	return true
}

// Set data
func (p *memProv) Set(_ context.Context, key string, v any, ttl time.Duration) error {
	if ttl == 0 {
		ttl = DefaultTTL
	}

	k := p.ns.key(key)
	b, err := json.Marshal(v)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal value: %s", k)
	}

	val := &entry{
		data: b,
	}

	if ttl != KeepTTL {
		exp := NowFunc().Add(ttl)
		val.expires = &exp
	}
	p.cache.Store(k, val)
	return nil
}

// Get data
func (p *memProv) Get(_ context.Context, key string, v any) error {
	k := p.ns.key(key)
	if ent, ok := p.cache.Load(k); ok {
		e := ent.(*entry)
		if e.live(NowFunc()) {
			err := json.Unmarshal(e.data, v)
			if err != nil {
				return errors.Wrapf(err, "failed to unmarshal value: %s", k)
			}
			return nil
		}
	}

	return errors.WithStack(ErrNotFound)
}

// Delete data
func (p *memProv) Delete(_ context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	for _, key := range keys {
		p.cache.Delete(p.ns.key(key))
	}
	return nil
}

// CleanExpired data
func (p *memProv) CleanExpired(_ context.Context) {
	now := NowFunc()
	p.cache.Range(func(key any, value any) bool {
		if !value.(*entry).live(now) {
			p.cache.Delete(key)
		}
		return true
	})
}

// Keys returns the live keys, relative to the provider, whose stored names
// match the Redis glob pattern as Redis KEYS would (see globMatch).
// This method should be used mostly for testing, as in prod many keys maybe returned
func (p *memProv) Keys(_ context.Context, pattern string) ([]string, error) {
	glob := p.ns.pattern(pattern)
	now := NowFunc()
	list := []string{}
	p.cache.Range(func(key any, value any) bool {
		name := key.(string)
		if value.(*entry).live(now) && globMatch(glob, name) {
			if rel, ok := p.ns.listed(pattern, name); ok {
				list = append(list, rel)
			}
		}
		return true
	})
	return list, nil
}

// listedKey is a key that ListKeys found, with its stored name, which
// orders the pages and is the cursor.
type listedKey struct {
	name string
	key  string
}

// pageHeap is a max-heap of listed keys by stored name (container/heap),
// so ListKeys keeps only the smallest names instead of sorting every match.
type pageHeap []listedKey

func (h pageHeap) Len() int           { return len(h) }
func (h pageHeap) Less(i, j int) bool { return h[i].name > h[j].name }
func (h pageHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

// Push adds x, a listedKey.
func (h *pageHeap) Push(x any) {
	*h = append(*h, x.(listedKey))
}

// Pop removes the last element, which container/heap made the largest.
func (h *pageHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// ListKeys returns up to count live keys, relative to the provider, whose
// stored names sort after cursor and match the Redis glob pattern as in
// Keys. The keys are in the byte order of their stored names, and the next
// cursor is the stored name of the last one, or "" when no match follows.
// It returns ctx.Err() when ctx is already done.
func (p *memProv) ListKeys(ctx context.Context, pattern, cursor string, count int) ([]string, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", errors.WithStack(err)
	}
	if count <= 0 {
		count = defaultListCount
	}
	glob := p.ns.pattern(pattern)
	now := NowFunc()
	// keep the count+1 smallest matching names: the extra one tells that
	// another page follows
	var found pageHeap
	p.cache.Range(func(key any, value any) bool {
		name := key.(string)
		// a stored name is never empty, so the empty cursor lists them all;
		// a full heap only takes a name below its largest
		if name <= cursor || (len(found) > count && name >= found[0].name) {
			return true
		}
		if !value.(*entry).live(now) || !globMatch(glob, name) {
			return true
		}
		if rel, ok := p.ns.listed(pattern, name); ok {
			heap.Push(&found, listedKey{
				name: name,
				key:  rel,
			})
			if len(found)-1 > count {
				heap.Pop(&found)
			}
		}
		return true
	})
	slices.SortFunc(found, func(a, b listedKey) int {
		return strings.Compare(a.name, b.name)
	})

	next := ""
	if len(found) > count {
		found = found[:count]
		next = found[count-1].name
	}
	keys := make([]string, len(found))
	for i, f := range found {
		keys[i] = f.key
	}
	return keys, next, nil
}

// Publish delivers message to every current subscriber of channel without
// waiting: a subscriber whose buffer is full misses the message.
func (p *memProv) Publish(ctx context.Context, channel, message string) error {
	if err := ctx.Err(); err != nil {
		return errors.WithStack(err)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for s := range p.subs {
		if s.channel == channel {
			select {
			case s.ch <- message:
			default:
				// slow subscriber: at-most-once delivery drops the message
			}
		}
	}

	return nil
}

// Subscribe registers a subscriber for channel; it fails only during or
// after Close, returning a failed subscription reporting ErrClosed.
func (p *memProv) Subscribe(_ context.Context, channel string) Subscription {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return closedSub(channel)
	}
	s := &msub{
		prov:    p,
		channel: channel,
		ch:      make(chan string, subscriberBufferSize),
		done:    make(chan struct{}),
	}
	p.subs[s] = struct{}{}
	return s
}

// unregister removes s from the live subscriptions.
func (p *memProv) unregister(s *msub) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.subs, s)
}

type msub struct {
	prov    *memProv
	channel string

	// ch carries published messages; it is not closed: Close signals done,
	// and Publish stops sending once Close unregistered the subscription
	// under the provider lock.
	ch chan string
	// done is closed by Close to unblock ReceiveMessage.
	done      chan struct{}
	closeOnce sync.Once
}

// Close unregisters the subscription; it is idempotent and unblocks a
// pending ReceiveMessage with ErrClosed.
func (s *msub) Close() error {
	s.closeOnce.Do(func() {
		s.prov.unregister(s)
		close(s.done)
	})
	return nil
}

// ReceiveMessage returns the next message, ctx.Err() when ctx is done or
// ErrClosed after Close.
func (s *msub) ReceiveMessage(ctx context.Context) (string, error) {
	select {
	case <-s.done:
		return "", errors.WithStack(ErrClosed)
	default:
	}
	select {
	case msg := <-s.ch:
		select {
		case <-s.done:
			// Close raced the delivery: buffered messages are discarded
			return "", errors.WithStack(ErrClosed)
		default:
			return msg, nil
		}
	case <-s.done:
		return "", errors.WithStack(ErrClosed)
	case <-ctx.Done():
		return "", errors.WithStack(ctx.Err())
	}
}
