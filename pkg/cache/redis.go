package cache

import (
	"cmp"
	"context"
	"encoding/json"
	"maps"
	"net/url"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

// subscribeTimeout bounds the wait for the server's subscription
// confirmation in Subscribe when ctx has no earlier deadline.
const subscribeTimeout = 10 * time.Second

type redisProv struct {
	ns     namespace
	cfg    RedisConfig
	client *redis.Client

	// mu guards subs and closed, so that Subscribe cannot register a
	// subscription that a concurrent Close would miss.
	mu sync.Mutex
	// subs holds the live subscriptions so that Close can release them
	// before the client is closed.
	subs   map[*rsub]struct{}
	closed bool
}

// NewRedisProvider returns a Provider backed by Redis. cfg.Server is parsed
// with redis.ParseURL, and a malformed URL is reported without the URL,
// which may embed a password; cfg.ClientTLS files (if set) configure TLS and
// cfg.Password overrides the URL credentials. An empty prefix becomes "/";
// a zero cfg.TTL becomes 1h. Maintenance notifications are disabled.
// The connection is established lazily, so a bad address only fails later.
func NewRedisProvider(cfg RedisConfig, prefix string) (Provider, error) {
	options, err := redis.ParseURL(cfg.Server)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			// url.Error repeats the URL
			err = uerr.Err
		}
		return nil, errors.WithMessage(err, "invalid redis address")
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

	options.MaintNotificationsConfig = &maintnotifications.Config{
		Mode: maintnotifications.ModeDisabled,
	}

	if cfg.TTL == 0 {
		cfg.TTL = time.Hour
	}
	prov := &redisProv{
		ns:     newNamespace(cmp.Or(prefix, "/")),
		cfg:    cfg,
		client: redis.NewClient(options),
		subs:   make(map[*rsub]struct{}),
	}

	return prov, nil
}

// Close closes every live subscription, then the client. A pending
// ReceiveMessage returns ErrClosed, buffered messages are discarded and a
// Subscribe during or after Close returns a failed subscription reporting
// ErrClosed.
// It is rare to Close a Client, as the Client is meant to be long-lived and shared between many goroutines.
func (p *redisProv) Close() error {
	p.mu.Lock()
	p.closed = true
	subs := slices.Collect(maps.Keys(p.subs))
	p.subs = nil
	p.mu.Unlock()

	var err error
	for _, s := range subs {
		if cerr := s.Close(); cerr != nil {
			err = errors.CombineErrors(err, cerr)
		}
	}
	if cerr := p.client.Close(); cerr != nil {
		err = errors.CombineErrors(err, errors.WithMessage(cerr, "failed to close redis client"))
	}
	return err
}

// isClosed reports whether Close was called.
func (p *redisProv) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// register adds s to the live subscriptions; it reports false when the
// provider is closed, in which case the caller releases s.
func (p *redisProv) register(s *rsub) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.subs[s] = struct{}{}
	return true
}

// unregister removes s from the live subscriptions.
func (p *redisProv) unregister(s *rsub) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.subs, s)
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

	k := p.ns.key(key)
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

	k := p.ns.key(key)
	val := p.client.Get(ctx, k)
	err := val.Err()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// FINDINGS P-095: the sentinel is not wrapped.
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
func (p *redisProv) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	pkeys := make([]string, 0, len(keys))
	for _, key := range keys {
		pkeys = append(pkeys, p.ns.key(key))
	}
	err := p.client.Del(ctx, pkeys...).Err()
	if err != nil {
		return errors.Wrapf(err, "failed to delete key")
	}
	return nil
}

// CleanExpired data
func (p *redisProv) CleanExpired(_ context.Context) {
	// redis exires keys
}

// Keys returns the keys, relative to the provider, that Redis KEYS matches
// with the Redis glob pattern.
// This method should be used mostly for testing, as in prod many keys maybe returned
func (p *redisProv) Keys(ctx context.Context, pattern string) ([]string, error) {
	list, err := p.client.Keys(ctx, p.ns.pattern(pattern)).Result()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list keys: %s", pattern)
	}
	keys := make([]string, 0, len(list))
	for _, name := range list {
		if rel, ok := p.ns.listed(pattern, name); ok {
			keys = append(keys, rel)
		}
	}
	return keys, nil
}

// Publish publishes message to channel. Redis never waits for subscribers.
func (p *redisProv) Publish(ctx context.Context, channel, message string) error {
	err := p.client.Publish(ctx, channel, message).Err()
	if err != nil {
		return errors.Wrapf(err, "failed to publish to channel %s", channel)
	}
	return nil
}

// Subscribe subscribes to channel and waits for the server to confirm the
// subscription, so a message published after Subscribe returns is
// delivered. The wait ends when ctx is done; otherwise connecting is
// bounded by the go-redis DialTimeout (attempted at most twice) and the
// confirmation read by subscribeTimeout. On failure the returned
// Subscription reports the error from ReceiveMessage: ErrClosed when the
// provider was closed before or during the wait.
func (p *redisProv) Subscribe(ctx context.Context, channel string) Subscription {
	if p.isClosed() {
		return closedSub(channel)
	}
	// go-redis writes SUBSCRIBE eagerly and records the channel afterwards,
	// even when the write failed. A failed write reconnects at once and
	// resubscribes only the channels recorded so far, so that connection
	// may have nothing subscribed and the confirmation below times out into
	// a failedSub; when that reconnect failed as well, the confirmation
	// read dials again and resubscribes from the recorded set, so it can
	// still succeed.
	ps := p.client.Subscribe(ctx, channel)
	if p.isClosed() {
		// Close may have run while go-redis set up the connection, which the
		// client does not track until it is ready, so Close may not have
		// closed it
		sub := closedSub(channel)
		if cerr := closePubSub(ps); cerr != nil {
			sub.err = errors.CombineErrors(sub.err, cerr)
		}
		return sub
	}
	err := confirmSubscription(ctx, ps)
	if err != nil {
		if cerr := closePubSub(ps); cerr != nil {
			err = errors.CombineErrors(err, cerr)
		}
		if p.isClosed() {
			// Close broke the connection that awaited the confirmation:
			// report the closed provider, keeping the go-redis error
			sub := closedSub(channel)
			sub.err = errors.WithSecondaryError(sub.err, err)
			return sub
		}
		return &failedSub{
			err: errors.Wrapf(err, "failed to subscribe to channel %s", channel),
		}
	}
	s := &rsub{
		prov: p,
		ps:   ps,
		// go-redis reads on its own goroutine, reconnects and resubscribes
		// after connection loss, and drops a message after waiting one
		// minute for a full channel.
		ch:   ps.Channel(redis.WithChannelSize(subscriberBufferSize)),
		done: make(chan struct{}),
	}
	if !p.register(s) {
		// Close ran meanwhile and could not see s: release its goroutines
		sub := closedSub(channel)
		if cerr := s.Close(); cerr != nil {
			sub.err = errors.CombineErrors(sub.err, cerr)
		}
		return sub
	}
	return s
}

// confirmSubscription waits for the server's reply to SUBSCRIBE. go-redis
// bounds the read by the ctx deadline and subscribeTimeout but does not
// watch ctx.Done, so a cancellation closes ps to unblock the read; the
// reader goroutine always exits within that bound.
func confirmSubscription(ctx context.Context, ps *redis.PubSub) error {
	confirmed := make(chan error, 1)
	go func() {
		reply, err := ps.ReceiveTimeout(ctx, subscribeTimeout)
		if err == nil {
			if _, ok := reply.(*redis.Subscription); !ok {
				err = errors.Errorf("unexpected reply %T", reply)
			}
		}
		confirmed <- err
	}()

	select {
	case err := <-confirmed:
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			// keep the go-redis error as a secondary diagnostic
			return errors.WithSecondaryError(errors.WithStack(ctx.Err()), err)
		}
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			// the socket deadline derived from ctx fired before ctx's timer
			return errors.WithSecondaryError(errors.WithStack(context.DeadlineExceeded), err)
		}
		return err
	case <-ctx.Done():
		err := errors.WithStack(ctx.Err())
		if cerr := closePubSub(ps); cerr != nil {
			err = errors.CombineErrors(err, cerr)
		}
		if rerr := <-confirmed; rerr != nil {
			err = errors.WithSecondaryError(err, rerr)
		}
		return err
	}
}

// closePubSub closes ps; a second close is not an error.
func closePubSub(ps *redis.PubSub) error {
	err := ps.Close()
	if err != nil && !errors.Is(err, redis.ErrClosed) {
		return errors.WithMessage(err, "failed to close subscription")
	}
	return nil
}

type rsub struct {
	prov *redisProv
	ps   *redis.PubSub
	// ch is fed by the go-redis reader goroutine, which closes it when the
	// client was closed.
	ch <-chan *redis.Message
	// done is closed by Close to unblock ReceiveMessage; the provider's
	// Close closes it too.
	done      chan struct{}
	closeOnce sync.Once
}

// Close closes the Redis subscription and stops its go-redis goroutines; it
// is idempotent and unblocks a pending ReceiveMessage with ErrClosed.
func (s *rsub) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		s.prov.unregister(s)
		err = closePubSub(s.ps)
		// The go-redis reader may be blocked sending into the full channel
		// and only watches its one-minute send timeout, not Close. Draining
		// unblocks it; it then observes the closed PubSub and closes ch,
		// which ends this goroutine.
		go func() {
			for range s.ch { // drain until the reader closes ch
			}
		}()
	})
	return err
}

// ReceiveMessage returns the next message, ctx.Err() when ctx is done or
// ErrClosed after Close or after the provider was closed. Connection loss
// is not reported: go-redis reconnects and resubscribes in the background.
func (s *rsub) ReceiveMessage(ctx context.Context) (string, error) {
	select {
	case <-s.done:
		return "", errors.WithStack(ErrClosed)
	default:
	}
	select {
	case msg, ok := <-s.ch:
		if !ok {
			// the reader stopped because the client was closed without the
			// provider's Close (which closes done first): release the
			// health-check goroutine, which only Close stops
			return "", errors.CombineErrors(errors.WithStack(ErrClosed), s.Close())
		}
		select {
		case <-s.done:
			// Close raced the delivery: buffered messages are discarded
			return "", errors.WithStack(ErrClosed)
		default:
			return msg.Payload, nil
		}
	case <-s.done:
		return "", errors.WithStack(ErrClosed)
	case <-ctx.Done():
		return "", errors.WithStack(ctx.Err())
	}
}
