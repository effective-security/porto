package cache

import (
	"context"
	"encoding/json"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/effective-security/x/guid"
	"github.com/pkg/errors"
)

type memProv struct {
	prefix string

	subs  sync.Map
	cache sync.Map
}

type entry struct {
	expires *time.Time
	// keep JSON encoded to be in parity with Redis
	data []byte
}

// NewMemoryProvider returns memory cache
func NewMemoryProvider(prefix string) Provider {
	prov := &memProv{
		prefix: prefix,
	}

	return prov
}

// Close closes the client, releasing any open resources.
// It is rare to Close a Client, as the Client is meant to be long-lived and shared between many goroutines.
func (p *memProv) Close() error {
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
func (p *memProv) Delete(_ context.Context, key string) error {
	k := path.Join(p.prefix, key)
	p.cache.Delete(k)
	return nil
}

// CleanExpired data
func (p *memProv) CleanExpired(_ context.Context) {
	now := NowFunc()
	p.cache.Range(func(key any, value any) bool {
		e := value.(*entry)
		if e.expires != nil && e.expires.After(now) {
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

	p.cache.Range(func(key any, value any) bool {
		name := key.(string)
		if strings.HasPrefix(name, k) {
			list = append(list, name)
		}
		return true
	})
	return list, nil
}

// Publish publishes message to channel
func (p *memProv) Publish(_ context.Context, channel, message string) error {
	p.subs.Range(func(key any, value any) bool {
		s := value.(*msub)
		if s.channel == channel {
			s.ch <- message
		}
		return true
	})

	return nil
}

// Subscribe subscribes to channel
func (p *memProv) Subscribe(_ context.Context, channel string) Subscription {
	s := &msub{
		prov:    p,
		channel: channel,
		id:      guid.MustCreate(),
		ch:      make(chan string, 10),
	}
	p.subs.Store(s.id, s)
	return s
}

type msub struct {
	prov    *memProv
	id      string
	channel string

	ch chan string
}

func (s *msub) Close() error {
	s.prov.subs.Delete(s.id)
	return nil
}

func (s *msub) ReceiveMessage(ctx context.Context) (string, error) {
	for {
		select {
		case msg := <-s.ch:
			return msg, nil
		case <-time.After(time.Second):
			if e := ctx.Err(); e != nil {
				return "", e
			}
		}
	}
}
