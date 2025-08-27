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

// DefaultTTL specifies default TTL
var DefaultTTL = 30 * time.Minute

// KeepTTL specifies to keep value
var KeepTTL = time.Duration(-1)

// NowFunc allows to override default time
var NowFunc = time.Now

// Config specifies configuration of the cache.
type Config struct {
	// Provider specifies the cache provider: redis|memory
	Provider string       `json:"provider" yaml:"provider"`
	Redis    *RedisConfig `json:"redis" yaml:"redis"`
}

// RedisConfig specifies configuration of the redis.
type RedisConfig struct {
	Server string        `json:"server,omitempty" yaml:"server,omitempty"`
	TTL    time.Duration `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// ClientTLS describes the TLS certs used to connect to the cluster
	ClientTLS *gserver.TLSInfo `json:"client_tls,omitempty" yaml:"client_tls,omitempty"`
	User      string           `json:"user,omitempty" yaml:"user,omitempty"`
	Password  string           `json:"password,omitempty" yaml:"password,omitempty"`
}

// Subscription defines subscription interface
type Subscription interface {
	// Close the subscription
	Close() error
	// ReceiveMessage returns message,
	// or error if subscription is closed
	ReceiveMessage(ctx context.Context) (string, error)
}

// Provider defines cache interface
type Provider interface {
	// Set data
	Set(ctx context.Context, key string, v any, ttl time.Duration) error
	// Get data
	Get(ctx context.Context, key string, v any) error
	// Delete data
	Delete(ctx context.Context, key string) error
	// CleanExpired data
	CleanExpired(ctx context.Context)
	// Close closes the client, releasing any open resources.
	// It is rare to Close a Client, as the Client is meant to be long-lived and shared between many goroutines.
	Close() error
	// Keys returns list of keys.
	// This method should be used mostly for testing, as in prod many keys maybe returned
	Keys(ctx context.Context, pattern string) ([]string, error)

	// IsLocal returns true, if cache is local
	IsLocal() bool

	// Publish publishes message to channel
	Publish(ctx context.Context, channel, message string) error
	// Subscribe subscribes to channel
	Subscribe(ctx context.Context, channel string) Subscription
}

// GetOrSet gets value from cache, or sets it using getter
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

// ErrNotFound defines not found error
var ErrNotFound = errors.New("not found")

// IsNotFoundError returns true, if error is NotFound
func IsNotFoundError(err error) bool {
	return err != nil &&
		(err == ErrNotFound || errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "not found"))
}
