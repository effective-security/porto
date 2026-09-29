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

// subscriberBufferSize is the number of undelivered messages a Subscription
// buffers for a subscriber that is not currently in ReceiveMessage. It is
// the memory provider's per-subscriber channel size and the go-redis
// message channel size for Redis subscriptions.
const subscriberBufferSize = 100

// Subscription is a channel subscription returned by Provider.Subscribe.
// Delivery is at most once: a subscriber that has fallen more than 100
// messages behind misses messages; see Provider.Publish.
type Subscription interface {
	// Close unregisters the subscription and releases its resources,
	// discarding buffered messages. It is idempotent, and it unblocks a
	// pending ReceiveMessage, which then returns ErrClosed. Closing the
	// provider closes its subscriptions; calling Close on them afterwards
	// is harmless. During an outage Close may wait for an
	// in-flight go-redis redial.
	Close() error
	// ReceiveMessage returns the next buffered message, or blocks until a
	// message arrives, ctx is done (returning ctx.Err()) or the
	// subscription is closed (returning ErrClosed). It returns promptly in
	// the last two cases and may be called from one goroutine at a time.
	// A Subscription that Subscribe could not establish returns the
	// subscribe error from every ReceiveMessage call. A Redis subscription
	// does not report connection loss: go-redis reconnects and resubscribes
	// in the background, and messages published meanwhile are lost.
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
	// Close closes the client, releasing any open resources. The memory
	// and Redis providers close their live subscriptions first, so a
	// pending ReceiveMessage returns ErrClosed and queued messages are
	// discarded; a Subscribe that runs during or after Close returns a
	// failed subscription that reports ErrClosed.
	// It is rare to Close a Client, as the Client is meant to be long-lived and shared between many goroutines.
	Close() error
	// Keys returns the keys matching pattern (glob for Redis, prefix match
	// for memory). It scans the whole keyspace and is meant for tests.
	Keys(ctx context.Context, pattern string) ([]string, error)

	// IsLocal returns true when the cache lives in this process only.
	IsLocal() bool

	// Publish sends message to every current subscriber of channel. It
	// never waits for a subscriber: a memory subscriber whose buffer of
	// 100 undelivered messages is full misses the message,
	// and a Redis subscriber is subject to the go-redis channel policy
	// (delivery waits up to one minute, then the message is dropped). A
	// Redis Publish also fails when ctx is done or the server is unreachable.
	Publish(ctx context.Context, channel, message string) error
	// Subscribe registers a subscriber for channel; call Close on the result
	// when done. A message published after Subscribe returns is delivered
	// to the new subscriber (Redis confirms the subscription with the
	// server before returning; the wait ends when ctx is done, returning
	// ctx.Err() through ReceiveMessage; otherwise connecting is bounded by
	// the go-redis dial timeout and the confirmation by 10 seconds).
	// Subscribe never returns nil: when the subscription could not be
	// established, or the provider is closed, the returned
	// Subscription reports the error from ReceiveMessage and its Close is
	// a no-op.
	Subscribe(ctx context.Context, channel string) Subscription
}

// GetOrSet decodes the cached value for key into value (a non-nil pointer).
// On a miss it calls getter, which must return a pointer, and copies the
// pointed-to result into value. A successful result is also stored with the
// provider's default TTL (Set with ttl 0). A cache write failure is returned
// without changing value. Interface destinations are unsupported on a miss
// because providers cannot reliably restore the getter's concrete type.
// Concurrent misses may call getter more than once.
// Errors other than a miss are returned as-is.
func GetOrSet(ctx context.Context, p Provider, key string, value any, getter func() (any, error)) error {
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return &json.InvalidUnmarshalError{Type: reflect.TypeOf(value)}
	}

	err := p.Get(ctx, key, value)
	if err == nil || !IsNotFoundError(err) {
		return err
	}
	if rv.Elem().Kind() == reflect.Interface {
		return errors.New("cache miss requires a concrete destination type")
	}
	if getter == nil {
		return errors.New("getter is nil")
	}

	res, err := getter()
	if err != nil {
		return err
	}
	result := reflect.ValueOf(res)
	if result.Kind() != reflect.Pointer || result.IsNil() {
		return &json.InvalidUnmarshalError{Type: reflect.TypeOf(res)}
	}
	result = result.Elem()
	if result.Kind() == reflect.Interface {
		if result.IsNil() {
			return errors.New("getter returned nil value")
		}
		result = result.Elem()
	}
	target := rv.Elem()
	if !result.Type().AssignableTo(target.Type()) {
		return errors.Errorf("getter returned %s, cannot assign to %s", result.Type(), target.Type())
	}
	if !result.CanInterface() {
		return errors.Errorf("getter result of type %s cannot be cached", result.Type())
	}
	if err := p.Set(ctx, key, result.Interface(), 0); err != nil {
		return errors.Wrapf(err, "failed to cache key %s", key)
	}
	target.Set(result)
	return nil
}

// ErrNotFound is returned by Get for a missing or expired key.
var ErrNotFound = errors.New("not found")

// ErrClosed is returned by Subscription.ReceiveMessage after Close or after
// the provider was closed, discarding buffered messages, and by the failed
// subscription that Subscribe returns during or after the provider's Close.
var ErrClosed = errors.New("subscription closed")

// failedSub is returned by Subscribe when the subscription could not be
// established; it holds no resources.
type failedSub struct {
	err error
}

// closedSub is the failed subscription returned by Subscribe during or
// after the provider's Close.
func closedSub(channel string) *failedSub {
	return &failedSub{
		err: errors.Wrapf(ErrClosed, "failed to subscribe to channel %s: provider closed", channel),
	}
}

// Close is a no-op: nothing was established.
func (s *failedSub) Close() error {
	return nil
}

// ReceiveMessage returns the subscribe error.
func (s *failedSub) ReceiveMessage(_ context.Context) (string, error) {
	return "", s.err
}

// IsNotFoundError reports whether err is (or wraps) ErrNotFound, or whose
// message contains "not found".
func IsNotFoundError(err error) bool {
	return err != nil &&
		(err == ErrNotFound || errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "not found"))
}
