package cache

import (
	"context"
	"fmt"
	"math"
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
	// nor does ListKeys, and the expired entry leaves no page to follow
	keys, next, err := p.ListKeys(ctx, "*", "", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"live"}, keys)
	assert.Empty(t, next)

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

		keys, next, err := p.ListKeys(ctx, "*", "", 1)
		require.NoError(t, err)
		assert.Equal(t, []string{"x"}, keys, prefix)
		assert.Empty(t, next, prefix)
		keys, next, err = p.ListKeys(ctx, "", "", 1)
		require.NoError(t, err)
		assert.Equal(t, []string{""}, keys, prefix)
		assert.Empty(t, next, prefix)
		keys, next, err = p.ListKeys(ctx, "none*", "", 1)
		require.NoError(t, err)
		assert.NotNil(t, keys, prefix)
		assert.Empty(t, keys, prefix)
		assert.Empty(t, next, prefix)
	}
}

func TestMemProv_ListKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	p := NewMemoryProvider("list")
	for _, key := range []string{"e", "a", "d", "b", "c", "x/1"} {
		require.NoError(t, p.Set(ctx, key, "v", time.Minute))
	}

	// pages hold count keys in stored-name order; the cursor is the
	// stored name of the last key
	keys, next, err := p.ListKeys(ctx, "?", "", 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, keys)
	assert.Equal(t, "list/b", next)
	keys, next, err = p.ListKeys(ctx, "?", next, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"c", "d"}, keys)
	assert.Equal(t, "list/d", next)
	keys, next, err = p.ListKeys(ctx, "?", next, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"e"}, keys)
	assert.Empty(t, next)

	// a full last page ends the iteration without an empty page
	keys, next, err = p.ListKeys(ctx, "?", "list/c", 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"d", "e"}, keys)
	assert.Empty(t, next)

	// between pages: a key added after the cursor is listed, one added
	// before it is not, and a deleted key is gone
	keys, next, err = p.ListKeys(ctx, "*", "", 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, keys)
	require.NoError(t, p.Set(ctx, "a2", "v", time.Minute))
	require.NoError(t, p.Set(ctx, "c2", "v", time.Minute))
	require.NoError(t, p.Delete(ctx, "c"))
	keys, next, err = p.ListKeys(ctx, "*", next, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"c2", "d"}, keys)
	keys, next, err = p.ListKeys(ctx, "*", next, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"e", "x/1"}, keys)
	assert.Empty(t, next)

	// count <= 0 is the default page size
	big := NewMemoryProvider("")
	for i := range defaultListCount + 1 {
		require.NoError(t, big.Set(ctx, fmt.Sprintf("k%03d", i), "v", time.Minute))
	}
	for _, count := range []int{0, -1} {
		keys, next, err = big.ListKeys(ctx, "*", "", count)
		require.NoError(t, err)
		assert.Len(t, keys, defaultListCount, count)
		assert.Equal(t, "/k099", next, count)
		keys, next, err = big.ListKeys(ctx, "*", next, count)
		require.NoError(t, err)
		assert.Equal(t, []string{"k100"}, keys, count)
		assert.Empty(t, next, count)
	}

	// a count that cannot overflow the page bound
	keys, next, err = p.ListKeys(ctx, "?", "", math.MaxInt)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "d", "e"}, keys)
	assert.Empty(t, next)

	// through a proxy, the cursor is the parent's stored name
	proxy := NewProxyProvider("x", p)
	keys, next, err = proxy.ListKeys(ctx, "*", "", 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"1"}, keys)
	assert.Empty(t, next)

	// a done ctx stops a paging loop, also through a proxy
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, prov := range []Provider{p, proxy} {
		keys, next, err = prov.ListKeys(canceled, "*", "", 1)
		assert.ErrorIs(t, err, context.Canceled)
		assert.EqualError(t, err, "context canceled")
		assert.Nil(t, keys)
		assert.Empty(t, next)
	}
}

// TestMemProv_ListKeysPageBound checks the page bound on fresh providers:
// sync.Map visits entries in a random order per map, so one provider would
// test only one order.
func TestMemProv_ListKeysPageBound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for range 64 {
		p := NewMemoryProvider("")
		for _, key := range []string{"c", "a", "b"} {
			require.NoError(t, p.Set(ctx, key, "v", time.Minute))
		}
		tcases := []struct {
			cursor string
			count  int
			keys   []string
			next   string
		}{
			{cursor: "", count: 1, keys: []string{"a"}, next: "/a"},
			{cursor: "", count: 2, keys: []string{"a", "b"}, next: "/b"},
			{cursor: "", count: 3, keys: []string{"a", "b", "c"}, next: ""},
			{cursor: "/a", count: 1, keys: []string{"b"}, next: "/b"},
			{cursor: "/a", count: 2, keys: []string{"b", "c"}, next: ""},
		}
		for _, tc := range tcases {
			keys, next, err := p.ListKeys(ctx, "*", tc.cursor, tc.count)
			require.NoError(t, err)
			require.Equal(t, tc.keys, keys, "cursor %q count %d", tc.cursor, tc.count)
			require.Equal(t, tc.next, next, "cursor %q count %d", tc.cursor, tc.count)
		}
	}
}

// TestMemProv_ListKeysConcurrent pages through the keys while other
// goroutines add and delete keys: every key that exists during the whole
// iteration is listed exactly once. Run with -race.
func TestMemProv_ListKeysConcurrent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	p := NewMemoryProvider("race")
	const stable = 200
	want := make([]string, stable)
	for i := range stable {
		want[i] = fmt.Sprintf("s%03d", i)
		require.NoError(t, p.Set(ctx, want[i], "v", time.Minute))
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(stop)
		wg.Wait()
	}()
	for w := range 4 {
		wg.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				// churn keys sort before, between and after the stable ones
				key := fmt.Sprintf("%c%d-%d", "asz"[i%3], w, i%50)
				if err := p.Set(ctx, key, "v", time.Minute); err != nil {
					t.Errorf("set %s: %v", key, err)
					return
				}
				if err := p.Delete(ctx, key); err != nil {
					t.Errorf("delete %s: %v", key, err)
					return
				}
			}
		})
	}

	for range 20 {
		seen := map[string]int{}
		cursor := ""
		for {
			keys, next, err := p.ListKeys(ctx, "*", cursor, 7)
			require.NoError(t, err)
			for _, key := range keys {
				seen[key]++
			}
			if next == "" {
				break
			}
			cursor = next
		}
		for key, n := range seen {
			assert.Equal(t, 1, n, "listed %s %d times", key, n)
		}
		for _, key := range want {
			assert.Contains(t, seen, key)
		}
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
