package cache

import (
	"context"
	"encoding/json"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

type memProv struct {
	prefix string

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

// NewMemoryProvider returns an in-process Provider whose keys are joined
// with prefix. Values are kept JSON encoded; the store is unbounded and
// expired entries are only dropped on Get or CleanExpired.
func NewMemoryProvider(prefix string) Provider {
	prov := &memProv{
		prefix: prefix,
		subs:   make(map[*msub]struct{}),
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

	k := path.Join(p.prefix, key)
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
	k := path.Join(p.prefix, key)
	if ent, ok := p.cache.Load(k); ok {
		e := ent.(*entry)
		if e.expires == nil || e.expires.After(NowFunc()) {
			err := json.Unmarshal(ent.(*entry).data, v)
			if err != nil {
				return errors.Wrapf(err, "failed to unmarshal value: %s", k)
			}
			return nil
		}
	}

	return ErrNotFound
}

// Delete data
func (p *memProv) Delete(_ context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	for _, key := range keys {
		k := path.Join(p.prefix, key)
		p.cache.Delete(k)
	}
	return nil
}

// CleanExpired data
func (p *memProv) CleanExpired(_ context.Context) {
	now := NowFunc()
	p.cache.Range(func(key any, value any) bool {
		e := value.(*entry)
		if e.expires != nil && !e.expires.After(now) {
			k := key.(string)
			p.cache.Delete(k)
		}
		return true
	})
}

// Keys returns list of keys.
// This method should be used mostly for testing, as in prod many keys maybe returned
func (p *memProv) Keys(_ context.Context, pattern string) ([]string, error) {
	k := path.Join(p.prefix, pattern)
	k = strings.TrimRight(k, "*?")

	var list []string

	p.cache.Range(func(key any, _ any) bool {
		name := key.(string)
		if strings.HasPrefix(name, k) {
			list = append(list, name)
		}
		return true
	})
	return list, nil
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
