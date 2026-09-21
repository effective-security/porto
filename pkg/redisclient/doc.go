// Package redisclient wraps github.com/redis/go-redis/v9 with a key
// prefix, JSON marshalling of values, error wrapping and a set of
// higher-level helpers: bounded ("with eviction") sets and hashes, a
// simple distributed lock and a one-execution-per-window rate limiter.
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
// Config YAML/JSON fields: server (redis:// or rediss:// URL), ttl,
// client_tls {cert, key, trusted_ca}, user, password. Password from Config
// overrides credentials embedded in the URL.
//
// Values: string and []byte are stored as-is, everything else is JSON
// encoded (see Marshal / UnmarshalStringCmd). Get and HGet return
// ErrNotFound for a missing key; the other commands return the wrapped
// go-redis error. WithPrefix returns a child that shares the connection
// and whose Close is a no-op; only the root client returned by New closes
// the connection.
package redisclient
