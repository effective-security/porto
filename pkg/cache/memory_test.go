package cache

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemProv_CleanExpired(t *testing.T) {
	ctx := context.Background()

	oldNow := NowFunc
	defer func() { NowFunc = oldNow }()
	base := time.Unix(0, 0)
	NowFunc = func() time.Time { return base }

	p := NewMemoryProvider("clean")
	require.NoError(t, p.Set(ctx, "live", "v", time.Hour))
	require.NoError(t, p.Set(ctx, "dead", "v", time.Millisecond))

	NowFunc = func() time.Time { return base.Add(2 * time.Millisecond) }

	// like Redis, Keys does not list an expired entry before it is cleaned
	keys, err := p.Keys(ctx, "*")
	require.NoError(t, err)
	assert.Equal(t, []string{"live"}, keys)

	p.CleanExpired(ctx)

	var out string
	assert.NoError(t, p.Get(ctx, "live", &out))
	assert.Equal(t, "v", out)
	assert.True(t, IsNotFoundError(p.Get(ctx, "dead", &out)))
	keys, err = p.Keys(ctx, "*")
	require.NoError(t, err)
	assert.Equal(t, []string{"live"}, keys)
}

func TestMemProv_KeysRoot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// an empty prefix is "/": the key "" is listed only for an empty
	// pattern, as under a named prefix
	for _, prefix := range []string{"", "named"} {
		p := NewMemoryProvider(prefix)
		require.NoError(t, p.Set(ctx, "", "root", time.Minute))
		require.NoError(t, p.Set(ctx, "x", "v", time.Minute))
		keys, err := p.Keys(ctx, "*")
		require.NoError(t, err)
		assert.Equal(t, []string{"x"}, keys, prefix)
		keys, err = p.Keys(ctx, "")
		require.NoError(t, err)
		assert.Equal(t, []string{""}, keys, prefix)
		keys, err = p.Keys(ctx, "none*")
		require.NoError(t, err)
		assert.NotNil(t, keys, prefix)
		assert.Empty(t, keys, prefix)
	}
}

// memTestTimeout bounds a Publish that must not block; memNoMessageWait is
// how long a receive waits to prove that nothing is delivered.
const (
	memTestTimeout   = 5 * time.Second
	memNoMessageWait = 20 * time.Millisecond
)

func TestMemProv_PublishSlowSubscriber(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	p := NewMemoryProvider("slow")
	sub := p.Subscribe(ctx, "chan")
	defer func() {
		assert.NoError(t, sub.Close())
	}()
	other := p.Subscribe(ctx, "other")
	defer func() {
		assert.NoError(t, other.Close())
	}()

	// publish more than the subscriber buffers without receiving anything;
	// Publish must not block on the full subscriber (formerly P-042)
	const extra = 5
	published := make(chan error, 1)
	go func() {
		for i := range subscriberBufferSize + extra {
			if err := p.Publish(ctx, "chan", strconv.Itoa(i)); err != nil {
				published <- err
				return
			}
		}
		published <- nil
	}()
	select {
	case err := <-published:
		require.NoError(t, err)
	case <-time.After(memTestTimeout):
		require.FailNow(t, "Publish blocked on a slow subscriber")
	}

	// the buffered messages arrive in order, the overflow is dropped
	for i := range subscriberBufferSize {
		msg, err := sub.ReceiveMessage(ctx)
		require.NoError(t, err)
		assert.Equal(t, strconv.Itoa(i), msg)
	}
	ctx2, cancel := context.WithTimeout(ctx, memNoMessageWait)
	defer cancel()
	_, err := sub.ReceiveMessage(ctx2)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	// a subscriber of another channel received nothing
	_, err = other.ReceiveMessage(ctx2)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	// the subscriber keeps working after the overflow
	require.NoError(t, p.Publish(ctx, "chan", "next"))
	msg, err := sub.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, "next", msg)
}

func TestMemProv_PublishContext(t *testing.T) {
	t.Parallel()

	p := NewMemoryProvider("pubctx")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := p.Publish(ctx, "chan", "msg")
	assert.ErrorIs(t, err, context.Canceled)
}

// TestMemProv_SubscribeDuringClose races Subscribe and Publish against
// Close: every subscription is closed by Close or rejected, none is left
// live, and a Subscribe after Close is rejected.
func TestMemProv_SubscribeDuringClose(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), memTestTimeout)
	defer cancel()

	const rounds = 50
	const subscribers = 8
	for range rounds {
		p := NewMemoryProvider("closing")
		subs := make(chan Subscription, subscribers)
		var wg sync.WaitGroup
		for range subscribers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				subs <- p.Subscribe(ctx, "chan")
				assert.NoError(t, p.Publish(ctx, "chan", "msg"))
			}()
		}
		require.NoError(t, p.Close())
		wg.Wait()
		close(subs)
		for sub := range subs {
			// a live subscription returns the published message or waits
			rctx, rcancel := context.WithTimeout(ctx, memNoMessageWait)
			_, err := sub.ReceiveMessage(rctx)
			rcancel()
			assert.ErrorIs(t, err, ErrClosed)
			assert.NoError(t, sub.Close())
		}
	}

	p := NewMemoryProvider("closed")
	require.NoError(t, p.Close())
	sub := p.Subscribe(ctx, "chan")
	assert.NoError(t, p.Publish(ctx, "chan", "nobody"))
	_, err := sub.ReceiveMessage(ctx)
	require.ErrorIs(t, err, ErrClosed)
	assert.Contains(t, err.Error(), "failed to subscribe to channel chan: provider closed")
	assert.NoError(t, sub.Close())
	assert.NoError(t, p.Close())
}

func TestMemProv_PubSubRace(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*memTestTimeout)
	defer cancel()

	p := NewMemoryProvider("race")
	const subscribers = 8
	const publishers = 4
	const messages = 200

	var wg sync.WaitGroup
	received := make([]atomic.Int64, subscribers)
	subs := make([]Subscription, subscribers)
	for i := range subscribers {
		subs[i] = p.Subscribe(ctx, "chan")
	}
	// a subscription closed while publishers are running is never sent to
	// after Close and never panics
	closing := p.Subscribe(ctx, "chan")

	for i := range subscribers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_, err := subs[i].ReceiveMessage(ctx)
				if err != nil {
					assert.True(t, errors.Is(err, ErrClosed) || errors.Is(err, context.DeadlineExceeded), err.Error())
					return
				}
				received[i].Add(1)
			}
		}()
	}

	var pubs sync.WaitGroup
	for range publishers {
		pubs.Add(1)
		go func() {
			defer pubs.Done()
			for i := range messages {
				assert.NoError(t, p.Publish(ctx, "chan", strconv.Itoa(i)))
				if i == messages/2 {
					assert.NoError(t, closing.Close())
				}
			}
		}()
	}
	pubs.Wait()
	_, err := closing.ReceiveMessage(ctx)
	assert.ErrorIs(t, err, ErrClosed)

	// every subscriber has at least one message buffered, so each receiver
	// gets one before Close discards the rest
	assert.Eventually(t, func() bool {
		for i := range subscribers {
			if received[i].Load() == 0 {
				return false
			}
		}
		return true
	}, memTestTimeout, time.Millisecond)

	// closing unblocks every receiver; the subscribers received at most
	// what was published (slow ones may have dropped messages)
	for _, s := range subs {
		assert.NoError(t, s.Close())
	}
	wg.Wait()
	for i := range subscribers {
		assert.LessOrEqual(t, received[i].Load(), int64(publishers*messages))
	}
}
