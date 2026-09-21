package cache

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
)

// DefaultTTL is the expiry applied by the memory provider when Set is
// called with ttl == 0. It is a package variable and may be changed at startup.
var DefaultTTL = 30 * time.Minute

// KeepTTL is the ttl value for Set that stores the value without expiry
// (Redis KEEPTTL semantics: an existing key keeps its TTL, a new key has none).
var KeepTTL = time.Duration(-1)

// NowFunc is the clock used by the memory provider for expiry; override
// it in tests to simulate time passing.
var NowFunc = time.Now

// Config specifies configuration of the cache. The package does not
// switch on Provider itself; callers choose NewMemoryProvider or
// NewRedisProvider(*Config.Redis, prefix).
type Config struct {
	// Provider specifies the cache provider: redis|memory
	Provider string `json:"provider" yaml:"provider"`
	// Redis holds the Redis connection settings when Provider is "redis".
	Redis *RedisConfig `json:"redis" yaml:"redis"`
}

// RedisConfig specifies the Redis connection used by NewRedisProvider.
type RedisConfig struct {
	// Server is the redis:// or rediss:// URL.
	Server string `json:"server,omitempty" yaml:"server,omitempty"`
	// TTL is the expiry applied when Set is called with ttl == 0; default 1h.
	TTL time.Duration `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// ClientTLS describes the TLS certs used to connect to the cluster
	ClientTLS *gserver.TLSInfo `json:"client_tls,omitempty" yaml:"client_tls,omitempty"`
	// User is the ACL user name; only applied when Password is set.
	User string `json:"user,omitempty" yaml:"user,omitempty"`
	// Password overrides the credentials embedded in Server.
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
}

// Subscription is a channel subscription returned by Provider.Subscribe.
type Subscription interface {
	// Close unregisters the subscription and releases its resources.
	Close() error
	// ReceiveMessage blocks until a message arrives or ctx is done
	// (checked about once per second), returning ctx.Err() in the latter case.
	ReceiveMessage(ctx context.Context) (string, error)
}

// Provider is the cache interface implemented by the memory, Redis and
// proxy providers. Implementations are safe for concurrent use.
type Provider interface {
	// Set stores v (JSON encoded, or raw for string/[]byte on Redis) under
	// key. ttl == 0 applies the provider default, KeepTTL disables expiry.
	Set(ctx context.Context, key string, v any, ttl time.Duration) error
	// Get decodes the value stored under key into v, which must be a
	// non-nil pointer. It returns ErrNotFound for a missing or expired key.
	Get(ctx context.Context, key string, v any) error
	// Delete removes the keys; missing keys are not an error.
	Delete(ctx context.Context, keys ...string) error
	// CleanExpired removes expired entries from the memory provider;
	// it is a no-op for Redis, which expires keys itself.
	CleanExpired(ctx context.Context)
	// Close closes the client, releasing any open resources.
	// It is rare to Close a Client, as the Client is meant to be long-lived and shared between many goroutines.
	Close() error
	// Keys returns the keys matching pattern (glob for Redis, prefix match
	// for memory). It scans the whole keyspace and is meant for tests.
	Keys(ctx context.Context, pattern string) ([]string, error)

	// IsLocal returns true when the cache lives in this process only.
	IsLocal() bool

	// Publish sends message to every subscriber of channel.
	Publish(ctx context.Context, channel, message string) error
	// Subscribe registers a subscriber for channel; call Close on the result
	// when done.
	Subscribe(ctx context.Context, channel string) Subscription
}

// GetOrSet decodes the cached value for key into value (a non-nil pointer).
// On a miss it calls getter, which must return a pointer, and copies the
// pointed-to result into value. Note that the result is NOT written back to
// the cache; callers must Set it themselves. Errors other than a miss are
// returned as-is.
func GetOrSet(ctx context.Context, p Provider, key string, value any, getter func() (any, error)) error {
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return &json.InvalidUnmarshalError{Type: reflect.TypeOf(value)}
	}

	var res any
	err := p.Get(ctx, key, value)
	if err != nil {
		if IsNotFoundError(err) {
			res, err = getter()
			if err == nil {
				rv2 := reflect.ValueOf(res)
				if rv2.Kind() != reflect.Pointer || rv2.IsNil() {
					return &json.InvalidUnmarshalError{Type: reflect.TypeOf(rv2)}
				}
				rv2 = reflect.Indirect(rv2)
				if rv2.Kind() == reflect.Interface {
					rv2 = rv2.Elem()
				}
				rv.Elem().Set(rv2)
			}
		}
	}
	return err
}

// ErrNotFound is returned by Get for a missing or expired key.
var ErrNotFound = errors.New("not found")

// IsNotFoundError reports whether err is (or wraps) ErrNotFound, or whose
// message contains "not found".
func IsNotFoundError(err error) bool {
	return err != nil &&
		(err == ErrNotFound || errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "not found"))
}
