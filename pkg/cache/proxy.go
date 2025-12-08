package cache

import (
	"context"
	"path"
	"time"
)

type proxyProv struct {
	prefix string
	prov   Provider
}

// NewProxyProvider returns proxy provider
func NewProxyProvider(prefix string, prov Provider) Provider {
	p := &proxyProv{
		prefix: prefix,
		prov:   prov,
	}

	return p
}

func (p *proxyProv) keyName(key string) string {
	return path.Join(p.prefix, key)
}

// Close closes the client, releasing any open resources.
// It is rare to Close a Client, as the Client is meant to be long-lived and shared between many goroutines.
func (p *proxyProv) Close() error {
	// this method does nothing as the parent must be closed safely
	return nil
}

// IsLocal returns true, if cache is local
func (p *proxyProv) IsLocal() bool {
	return p.prov.IsLocal()
}

// Set data
func (p *proxyProv) Set(ctx context.Context, key string, v any, ttl time.Duration) error {
	return p.prov.Set(ctx, p.keyName(key), v, ttl)
}

// Get data
func (p *proxyProv) Get(ctx context.Context, key string, v any) error {
	return p.prov.Get(ctx, p.keyName(key), v)
}

// Delete data
func (p *proxyProv) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	pkeys := make([]string, 0, len(keys))
	for _, key := range keys {
		pkeys = append(pkeys, p.keyName(key))
	}
	return p.prov.Delete(ctx, pkeys...)
}

// CleanExpired data
func (p *proxyProv) CleanExpired(ctx context.Context) {
	p.prov.CleanExpired(ctx)
}

// Keys returns list of keys.
// This method should be used mostly for testing, as in prod many keys maybe returned
func (p *proxyProv) Keys(ctx context.Context, pattern string) ([]string, error) {
	return p.prov.Keys(ctx, p.keyName(pattern))
}

// Subscribe subscribes to channel
func (p *proxyProv) Subscribe(ctx context.Context, channel string) Subscription {
	return p.prov.Subscribe(ctx, channel)
}

// Publish publishes message to channel
func (p *proxyProv) Publish(ctx context.Context, channel, message string) error {
	return p.prov.Publish(ctx, channel, message)
}
