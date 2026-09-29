// Package cache provides a small key/value cache abstraction (Provider)
// with a TTL per entry, a pattern-based key listing and a minimal
// publish/subscribe channel, backed either by process memory or by Redis.
//
// Values are JSON encoded on Set and decoded into the pointer passed to
// Get, so both backends behave the same. A missing or expired entry is
// reported as ErrNotFound (test with IsNotFoundError). Keys are joined
// with the provider prefix using path.Join.
//
//	var p cache.Provider
//	if cfg.Provider == "redis" {
//		p, err = cache.NewRedisProvider(*cfg.Redis, "/myapp")
//	} else {
//		p = cache.NewMemoryProvider("/myapp")
//	}
//	err = p.Set(ctx, "user:1", user, 10*time.Minute) // 0 => default TTL, cache.KeepTTL => no expiry
//	var u User
//	err = p.Get(ctx, "user:1", &u)
//
//	// scope a shared provider to a sub-namespace
//	users := cache.NewProxyProvider("users", p)
//
// Config YAML/JSON fields: provider (redis|memory) and redis {server, ttl,
// client_tls {cert, key, trusted_ca}, user, password}. The package does not
// itself switch on Config.Provider; the caller picks the constructor.
//
// TTL: a ttl of 0 means DefaultTTL for the memory provider and
// RedisConfig.TTL (default 1h) for Redis; KeepTTL stores the value without
// expiry (Redis KEEPTTL). The memory provider never evicts on its own: the
// caller must run CleanExpired periodically, and NowFunc can be overridden
// in tests to control its clock.
// GetOrSet reads through the cache on a miss and stores a successful getter
// result with the provider's default TTL. The getter returns a pointer to the
// value to store. On a miss, the destination must point to a concrete type;
// providers cannot reliably restore values into interface destinations.
// Concurrent misses may run the getter more than once.
//
// Pub/Sub: Subscribe returns a Subscription whose ReceiveMessage returns
// the next message, ctx.Err() as soon as the context is done, or ErrClosed
// after Close; Close is idempotent, and closing the provider closes its
// subscriptions (a Subscribe during or after that Close returns a
// subscription reporting ErrClosed). A message published after Subscribe
// returns reaches the new subscriber: the Redis provider waits for the
// server to confirm the subscription, and a subscription it could not
// establish reports the error from ReceiveMessage. Delivery is at most
// once and Publish never waits for a subscriber: each subscriber buffers
// 100 undelivered messages; a memory subscriber whose buffer is full misses
// the message, and a Redis subscriber follows the go-redis channel policy
// (its reader waits up to one minute, then drops the message). The memory
// provider delivers in-process only; the Redis provider uses Redis
// channels, which are not prefixed.
//
//	sub := p.Subscribe(ctx, "invalidate")
//	defer sub.Close()
//	for {
//		msg, err := sub.ReceiveMessage(ctx)
//		if err != nil {
//			return err // ctx done, ErrClosed, or the subscription failed
//		}
//		handle(msg)
//	}
package cache
