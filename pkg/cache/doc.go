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
//
// Pub/Sub: Subscribe returns a Subscription whose ReceiveMessage blocks
// until a message arrives or the context is done (checked about once a
// second); Close unregisters it. The memory provider delivers to every
// subscriber of the channel in-process only; the Redis provider uses Redis
// channels, which are not prefixed.
package cache
