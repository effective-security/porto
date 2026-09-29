// Package redisclient wraps github.com/redis/go-redis/v9 with a key
// prefix, JSON marshalling of values, error wrapping and a set of
// higher-level helpers: bounded ("with eviction") sets and hashes, an
// owner-bound distributed lock and a one-execution-per-window rate limiter.
//
// RedisClient embeds *redis.Client, so raw commands remain available, while
// the wrapper methods apply the prefix via Key. Provider is the interface
// implemented by RedisClient and is what consumers should depend on.
//
//	rc, err := redisclient.New(&redisclient.Config{
//		Server:   "redis://localhost:6379/0",
//		Password: "secret",
//	})
//	if err != nil {
//		return err
//	}
//	defer rc.Close()
//
//	c := rc.WithPrefix("myapp") // keys become "/myapp/<key>"
//	if err := c.Set(ctx, "user:1", user, time.Hour); err != nil {
//		return err
//	}
//	var u User
//	if err := c.Get(ctx, "user:1", &u); redisclient.IsNotFoundError(err) {
//		// missing
//	}
//
//	token, remaining, err := c.TryLock(ctx, "job", 30*time.Second)
//	if err != nil {
//		return err
//	}
//	if token == "" {
//		return fmt.Errorf("job is locked for %s", remaining)
//	}
//	defer c.ReleaseLock(ctx, "job", token) // only while token holds the lock
//
// Config YAML/JSON fields: server (redis:// or rediss:// URL), ttl,
// client_tls {cert, key, trusted_ca}, user, password. Password from Config
// overrides credentials embedded in the URL. Only the server address and
// database are logged; a malformed URL is reported without the URL.
//
// Keys: a key is cleaned as a rooted path and joined with the prefix, so
// ".." cannot leave the prefix, and lock and rate-limit keys cannot leave
// their "lock:" and "ratelimit:" namespaces; Keys and ScanKeys take Redis
// glob patterns relative to the prefix, match the prefix literally and
// return relative keys.
//
// Values: string and []byte are stored as-is, everything else is JSON
// encoded (see Marshal / UnmarshalStringCmd). Get and HGet return
// ErrNotFound for a missing key; the other commands return the wrapped
// go-redis error. WithPrefix returns a child that shares the connection
// and whose Close is a no-op; only the root client returned by New closes
// the connection, and after that the commands of the root and its
// children fail with redis.ErrClosed.
//
// Coordination: TryLock returns a random owner token and ReleaseLock
// deletes the lock only while it still holds that token (a Lua
// compare-and-delete), so an expired owner cannot release a successor's
// lock. TryAcquireRateLimit starts a window with SET NX PX: one call per
// window succeeds, denied calls write nothing, and the window is measured
// by the server's clock. SAddWithEviction and HSetWithEviction update the
// collection and its insertion-order list in one Lua script. The server
// must allow Lua scripting (EVALSHA).
package redisclient
