package cache

import (
	"context"
	"encoding/json"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

type redisProv struct {
	prefix string
	cfg    RedisConfig
	client *redis.Client
}

// NewRedisProvider returns Redis cache
func NewRedisProvider(cfg RedisConfig, prefix string) (Provider, error) {
	options, err := redis.ParseURL(cfg.Server)
	if err != nil {
		return nil, errors.WithMessagef(err, "invalid redis address")
	}

	if cfg.ClientTLS != nil {
		tlscfg, err := tlsconfig.NewClientTLSFromFiles(
			cfg.ClientTLS.CertFile,
			cfg.ClientTLS.KeyFile,
			cfg.ClientTLS.TrustedCAFile)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to build TLS configuration")
		}

		options.TLSConfig = tlscfg
	}
	if cfg.Password != "" {
		options.Username = cfg.User
		options.Password = cfg.Password
	}

	if cfg.TTL == 0 {
		cfg.TTL = time.Hour
	}
	if prefix == "" {
		prefix = "/"
	}
	prov := &redisProv{
		prefix: prefix,
		cfg:    cfg,
		client: redis.NewClient(options),
	}

	return prov, nil
}

// Close closes the client, releasing any open resources.
// It is rare to Close a Client, as the Client is meant to be long-lived and shared between many goroutines.
func (p *redisProv) Close() error {
	return p.client.Close()
}

// IsLocal returns true, if cache is local
func (p *redisProv) IsLocal() bool {
	return false
}

// Set data
func (p *redisProv) Set(ctx context.Context, key string, v any, ttl time.Duration) error {
	if ttl == 0 {
		ttl = p.cfg.TTL
	}

	var value any
	switch t := v.(type) {
	case string:
		value = t
	case []byte:
		value = t
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return errors.Wrapf(err, "failed to marshal value: %s", key)
		}
		value = string(b)
	}

	k := path.Join(p.prefix, key)
	err := p.client.Set(ctx, k, value, ttl).Err()
	if err != nil {
		return errors.Wrapf(err, "failed to set key: %s", k)
	}
	return nil
}

// Get data
func (p *redisProv) Get(ctx context.Context, key string, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return &json.InvalidUnmarshalError{Type: reflect.TypeOf(v)}
	}

	k := path.Join(p.prefix, key)
	val := p.client.Get(ctx, k)
	err := val.Err()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrNotFound
		}
		return errors.Wrapf(err, "failed to get key: %s", k)
	}

	switch t := v.(type) {
	case *string:
		*t = val.Val()
	case *[]byte:
		b, err := val.Bytes()
		if err != nil {
			return errors.Wrapf(err, "failed to get key: %s", k)
		}
		*t = b
	default:
		b, err := val.Bytes()
		if err != nil {
			return errors.Wrapf(err, "failed to get key: %s", k)
		}
		err = json.Unmarshal(b, v)
		if err != nil {
			return errors.Wrapf(err, "failed to unmarshal value: %s", k)
		}
	}

	return nil
}

// Delete data
func (p *redisProv) Delete(ctx context.Context, key string) error {
	k := path.Join(p.prefix, key)
	err := p.client.Del(ctx, k).Err()
	if err != nil {
		return errors.Wrapf(err, "failed to delete key: %s", k)
	}
	return nil
}

// CleanExpired data
func (p *redisProv) CleanExpired(_ context.Context) {
	// redis exires keys
}

// Keys returns list of keys.
// This method should be used mostly for testing, as in prod many keys maybe returned
func (p *redisProv) Keys(ctx context.Context, pattern string) ([]string, error) {
	k := path.Join(p.prefix, pattern)
	res := p.client.Keys(ctx, k)
	if res.Err() != nil {
		return nil, res.Err()
	}
	list := res.Val()
	for i, key := range list {
		list[i] = strings.TrimPrefix(key, p.prefix)
	}
	return list, nil
}

// Publish publishes message to channel
func (p *redisProv) Publish(ctx context.Context, channel, message string) error {
	return p.client.Publish(ctx, channel, message).Err()
}

// Subscribe subscribes to channel
func (p *redisProv) Subscribe(ctx context.Context, channel string) Subscription {
	return &rsub{p.client.Subscribe(ctx, channel)}
}

type rsub struct {
	prov *redis.PubSub
}

func (s *rsub) Close() error {
	return s.prov.Close()
}
func (s *rsub) ReceiveMessage(ctx context.Context) (string, error) {
	// Redis 9 has a bug that ReceiveMessage does not return error on timeout

	ch := make(chan any)

	go func() {
		msg, err := s.prov.ReceiveMessage(ctx)
		if err != nil {
			ch <- err
		} else {
			ch <- msg
		}
	}()

	for {
		select {
		case msg := <-ch:
			if err, ok := msg.(error); ok {
				return "", err
			}
			return msg.(*redis.Message).Payload, nil
		case <-time.After(time.Second):
			if e := ctx.Err(); e != nil {
				return "", e
			}
		}
	}
}
