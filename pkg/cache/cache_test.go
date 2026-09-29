package cache_test

import (
	"bufio"
	"context"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/effective-security/xpki/certutil"
	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	rediscon "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestProvider(t *testing.T) {
	ctx := context.Background()
	redisContainer, err := rediscon.Run(ctx, "redis:8.2",
		testcontainers.WithConfigModifier(func(config *container.Config) {
			config.Env = []string{
				"ALLOW_EMPTY_PASSWORD=yes",
				"REDIS_PASSWORD=redis",
				"REDIS_TLS_PORT=16379",
			}
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, redisContainer.Terminate(ctx))
	})

	root := "test-" + certutil.RandomString(4)

	host, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	t.Run("redis", func(t *testing.T) {
		r, err := cache.NewRedisProvider(cache.RedisConfig{
			Server:   host,
			Password: "redis",
		}, root)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, r.Close())
		}()
		assert.False(t, r.IsLocal())

		provTest(t, r, root)
	})

	t.Run("redis provider closed", func(t *testing.T) {
		r, err := cache.NewRedisProvider(cache.RedisConfig{
			Server:   host,
			Password: "redis",
		}, root)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(ctx, pubsubTimeout)
		defer cancel()
		const chanName = "closed-provider"
		sub := r.Subscribe(ctx, chanName)
		// a delivered marker proves the subscription is live; the second
		// message stays queued in the subscription
		require.NoError(t, r.Publish(ctx, chanName, "marker"))
		require.NoError(t, r.Publish(ctx, chanName, "queued"))
		rr := awaitResult(t, receiveAsync(ctx, sub), pubsubTimeout)
		require.NoError(t, rr.err)
		assert.Equal(t, "marker", rr.msg)

		pending := r.Subscribe(ctx, chanName)
		res := receiveAsync(ctx, pending)
		require.NoError(t, r.Close())

		// the pending receive reports the closed provider, the queued
		// message is discarded and the go-redis goroutines are released
		// without Close on the subscriptions
		rr = awaitResult(t, res, pubsubTimeout)
		assert.ErrorIs(t, rr.err, cache.ErrClosed)
		_, err = sub.ReceiveMessage(ctx)
		assert.ErrorIs(t, err, cache.ErrClosed)
		assert.Eventually(t, func() bool {
			return pubsubGoroutines() == 0
		}, pubsubTimeout, 20*time.Millisecond, "go-redis pub/sub goroutines leaked")
		assert.NoError(t, sub.Close())
		assert.NoError(t, pending.Close())
	})

	t.Run("redis subscribe during close", func(t *testing.T) {
		r, err := cache.NewRedisProvider(cache.RedisConfig{
			Server:   host,
			Password: "redis",
		}, root)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(ctx, pubsubTimeout)
		defer cancel()
		const chanName = "closing"
		const subscribers = 8
		subs := make(chan cache.Subscription, subscribers)
		var wg sync.WaitGroup
		for range subscribers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				subs <- r.Subscribe(ctx, chanName)
			}()
		}
		// close while subscriptions are being established: each one is
		// either closed by the provider or rejected, never left live
		require.NoError(t, r.Close())
		wg.Wait()
		close(subs)
		for sub := range subs {
			_, err := sub.ReceiveMessage(ctx)
			assert.ErrorIs(t, err, cache.ErrClosed)
			assert.NoError(t, sub.Close())
		}

		// after Close, Subscribe is rejected without a round trip
		sub := r.Subscribe(ctx, chanName)
		_, err = sub.ReceiveMessage(ctx)
		require.ErrorIs(t, err, cache.ErrClosed)
		assert.Contains(t, err.Error(), "provider closed")
		assert.NoError(t, sub.Close())

		assert.Eventually(t, func() bool {
			return pubsubGoroutines() == 0
		}, pubsubTimeout, 20*time.Millisecond, "go-redis pub/sub goroutines leaked")
	})

	t.Run("redis slow subscriber closed", func(t *testing.T) {
		r, err := cache.NewRedisProvider(cache.RedisConfig{
			Server:   host,
			Password: "redis",
		}, root)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, r.Close())
		}()

		ctx, cancel := context.WithTimeout(ctx, pubsubTimeout)
		defer cancel()
		const chanName = "slow-subscriber"
		sub := r.Subscribe(ctx, chanName)
		// overflow the subscriber buffer so the go-redis reader blocks on
		// its send, then Close must release it without waiting for the
		// go-redis one-minute send timeout
		for i := range 2 * cache.SubscriberBufferSize {
			require.NoError(t, r.Publish(ctx, chanName, strconv.Itoa(i)))
		}
		require.Eventually(t, readerBlockedOnSend, pubsubTimeout, 20*time.Millisecond,
			"go-redis reader did not block on the full channel")

		require.NoError(t, sub.Close())
		_, err = sub.ReceiveMessage(ctx)
		assert.ErrorIs(t, err, cache.ErrClosed)
		assert.Eventually(t, func() bool {
			return pubsubGoroutines() == 0
		}, pubsubTimeout, 20*time.Millisecond, "go-redis reader leaked after Close")
	})

	mem := cache.NewMemoryProvider(root)
	defer func() {
		assert.NoError(t, mem.Close())
	}()
	assert.True(t, mem.IsLocal())

	t.Run("memory", func(t *testing.T) {
		provTest(t, mem, root)
	})

	t.Run("memory provider closed", func(t *testing.T) {
		m := cache.NewMemoryProvider(root)
		ctx, cancel := context.WithTimeout(ctx, pubsubTimeout)
		defer cancel()
		const chanName = "closed-provider"
		sub := m.Subscribe(ctx, chanName)
		require.NoError(t, m.Publish(ctx, chanName, "queued"))
		pending := m.Subscribe(ctx, chanName)
		res := receiveAsync(ctx, pending)

		require.NoError(t, m.Close())
		r := awaitResult(t, res, promptTimeout)
		assert.ErrorIs(t, r.err, cache.ErrClosed)
		_, err := sub.ReceiveMessage(ctx)
		assert.ErrorIs(t, err, cache.ErrClosed)
		assert.NoError(t, sub.Close())
		assert.NoError(t, pending.Close())
	})

	t.Run("proxy", func(t *testing.T) {
		pr := cache.NewProxyProvider("subkey", mem)
		defer func() {
			assert.NoError(t, pr.Close())
		}()
		assert.True(t, pr.IsLocal())
		provTest(t, pr, root)
	})

	t.Run("keys parity", func(t *testing.T) {
		// glob metacharacters in the prefix must match literally: unescaped,
		// the pattern for "ns*[1]?" would also list the sibling "nsX1Y"
		prefix := root + "/ns*[1]?"
		r, err := cache.NewRedisProvider(cache.RedisConfig{
			Server:   host,
			Password: "redis",
		}, prefix)
		require.NoError(t, err)
		sibling, err := cache.NewRedisProvider(cache.RedisConfig{
			Server:   host,
			Password: "redis",
		}, root+"/nsX1Y")
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, sibling.Delete(ctx, "a"))
			assert.NoError(t, r.Close())
			assert.NoError(t, sibling.Close())
		}()
		require.NoError(t, sibling.Set(ctx, "a", "v", time.Minute))

		keysParity(t, r, cache.NewMemoryProvider(prefix))
		keysParity(t, cache.NewProxyProvider("/p[x]/", r), cache.NewProxyProvider("p[x]", cache.NewMemoryProvider(prefix)))
	})

	t.Run("redis namespace", func(t *testing.T) {
		newProv := func(prefix string) cache.Provider {
			p, err := cache.NewRedisProvider(cache.RedisConfig{
				Server:   host,
				Password: "redis",
			}, root+prefix)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, p.Close())
			})
			return p
		}
		namespaceTest(t, newProv("/tenant-a"), newProv("/tenant-b"))
	})

	t.Run("redis dot prefix", func(t *testing.T) {
		// a prefix that cleans to "." stores relative names; its Keys must
		// not list the names of the root provider, which it cannot read
		newProv := func(prefix string) cache.Provider {
			p, err := cache.NewRedisProvider(cache.RedisConfig{
				Server:   host,
				Password: "redis",
			}, prefix)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, p.Close())
			})
			return p
		}
		dot, slash := newProv("."), newProv("")
		rel, abs := root+"-dot", root+"-slash"
		require.NoError(t, dot.Set(ctx, rel, "v", time.Minute))
		require.NoError(t, slash.Set(ctx, abs, "v", time.Minute))
		t.Cleanup(func() {
			assert.NoError(t, dot.Delete(ctx, rel))
			assert.NoError(t, slash.Delete(ctx, abs))
		})

		// "*" also matches "/<abs>" in Redis; other subtests' relative
		// names may be listed too
		keys, err := dot.Keys(ctx, "*")
		require.NoError(t, err)
		assert.Contains(t, keys, rel)
		for _, key := range keys {
			assert.False(t, strings.HasPrefix(key, "/"), "listed %q, which Get cannot read", key)
		}
		keys, err = slash.Keys(ctx, root+"-*")
		require.NoError(t, err)
		assert.Equal(t, []string{abs}, keys)
	})

	t.Run("memory namespace", func(t *testing.T) {
		m := cache.NewMemoryProvider(root)
		namespaceTest(t, cache.NewProxyProvider("tenant-a", m), cache.NewProxyProvider("tenant-b", m))
	})
}

// keysParity stores the same keys in a Redis-backed and a memory-backed
// provider and checks that Keys returns the same relative keys for each
// pattern, so the memory glob matches Redis KEYS.
func keysParity(t *testing.T, r, m cache.Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keys := []string{
		"", "a", "ab", "abc", "a/b", "a/b/c", "b[1]", "b*", "b?x", `x\y`, "é",
		"user:1:profile", "user:22:profile", "user:1:settings",
		"hello", "hallo", "hllo", "heeello", "Z", "-", "]", "^",
	}
	for _, p := range []cache.Provider{r, m} {
		for _, key := range keys {
			require.NoError(t, p.Set(ctx, key, "v", time.Minute))
		}
	}
	defer func() {
		assert.NoError(t, r.Delete(ctx, keys...))
	}()

	patterns := []string{
		"", "*", "**", "?", "??", "???", "a*", "a?", "a/*", "*/*", "*b*", "*/c",
		"[ab]*", "[^a]*", "[a-b]*", "[b-a]*", "[A-Z]", "[a-z]", "[-]", `[\]]`, "[]]",
		"[^]]", "[", "a[", "[ab", "[^", `\`, `a\`, `b\[*`, `b\*`, `b\?x`, `x\\y`,
		"h[ae]llo", "h[^e]llo", "h*llo", "h?llo", "*o", "*?*", "user:*:profile",
		"*:profile", "u*1*", "é", "../*", "a/../*", "/a/", ".", "..",
	}
	for _, pattern := range patterns {
		rkeys, err := r.Keys(ctx, pattern)
		require.NoError(t, err)
		mkeys, err := m.Keys(ctx, pattern)
		require.NoError(t, err)
		assert.ElementsMatch(t, rkeys, mkeys, "pattern %q", pattern)
	}

	// the relative keys round-trip through Get
	all, err := r.Keys(ctx, "*")
	require.NoError(t, err)
	assert.ElementsMatch(t, keys[1:], all)
	root, err := r.Keys(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, []string{""}, root)
	for _, key := range all {
		var v string
		require.NoError(t, r.Get(ctx, key, &v), key)
		require.NoError(t, m.Get(ctx, key, &v), key)
	}
}

// namespaceTest checks that keys with ".." segments and proxy prefixes stay
// inside their provider's namespace (formerly P-044): a and b are siblings
// "tenant-a" and "tenant-b" sharing one backend.
func namespaceTest(t *testing.T, a, b cache.Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var v string
	require.NoError(t, a.Set(ctx, "../tenant-b/x", "from-a", time.Minute))
	require.True(t, cache.IsNotFoundError(b.Get(ctx, "x", &v)), "key escaped into the sibling")
	require.NoError(t, a.Get(ctx, "tenant-b/x", &v))
	assert.Equal(t, "from-a", v)

	escape := cache.NewProxyProvider("../tenant-b", a)
	require.NoError(t, escape.Set(ctx, "y", "via-proxy", time.Minute))
	require.True(t, cache.IsNotFoundError(b.Get(ctx, "y", &v)), "proxy prefix escaped into the sibling")
	require.NoError(t, a.Get(ctx, "tenant-b/y", &v))
	assert.Equal(t, "via-proxy", v)

	// the proxy is "tenant-a/tenant-b", which also holds the first key
	keys, err := escape.Keys(ctx, "*")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"x", "y"}, keys)
	keys, err = a.Keys(ctx, "*")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"tenant-b/x", "tenant-b/y"}, keys)
	keys, err = b.Keys(ctx, "*")
	require.NoError(t, err)
	assert.Empty(t, keys)
	assert.NotNil(t, keys)

	require.NoError(t, a.Delete(ctx, "tenant-b/x", "../tenant-b/y"))
	keys, err = a.Keys(ctx, "*")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestRedisProviderConfigSecrets(t *testing.T) {
	t.Parallel()
	_, err := cache.NewRedisProvider(cache.RedisConfig{
		Server: "redis://user:s3cret-pass@127.0.0.1:bad/0",
	}, "")
	require.EqualError(t, err, `invalid redis address: invalid port ":bad" after host`)
}

func provTest(t *testing.T, p cache.Provider, root string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var strVal string
	var strsVal []string
	var bVal []byte
	var cfgVal cache.Config
	var boolVal bool
	var uintVal uint64
	var float32Val float32
	var float64Val float64

	err := p.Get(ctx, "notfound", &strVal)
	assert.True(t, cache.IsNotFoundError(err))

	tcases := []struct {
		name string
		in   any
		out  any
	}{
		{
			name: "float32",
			in:   float32(12.3456),
			out:  &float32Val,
		},
		{
			name: "float64",
			in:   float64(12.345678),
			out:  &float64Val,
		},
		{
			name: "bytes",
			in:   []byte(`1234`),
			out:  &bVal,
		},
		{
			name: "bool",
			in:   true,
			out:  &boolVal,
		},
		{
			name: "uint",
			in:   uint64(123456789),
			out:  &uintVal,
		},
		{
			name: "string",
			in:   "str",
			out:  &strVal,
		},
		{
			name: "strings",
			in:   []string{"str1", "str2", "str3"},
			out:  &strsVal,
		},
		{
			name: "struct",
			in: cache.Config{
				Provider: "redis",
				Redis: &cache.RedisConfig{
					Server: "local",
				},
			},
			out: &cfgVal,
		},
	}

	t.Run("interface destination on miss", func(t *testing.T) {
		var value any
		err := cache.GetOrSet(ctx, p, "interface-miss", &value, func() (any, error) {
			result := "computed"
			return &result, nil
		})
		require.EqualError(t, err, "cache miss requires a concrete destination type")
		err = p.Get(ctx, "interface-miss", &value)
		require.True(t, cache.IsNotFoundError(err))
	})

	defer func() {
		// let's not polute redis
		for _, tc := range tcases {
			_ = p.Delete(ctx, tc.name)
		}
	}()

	for _, tc := range tcases {
		getterCalls := 0
		err = cache.GetOrSet(ctx, p, tc.name, tc.out, func() (any, error) {
			getterCalls++
			return &tc.in, nil
		})
		require.NoError(t, err)
		testutils.CompareJSON(t, tc.in, tc.out)

		err = p.Get(ctx, tc.name, tc.out)
		require.NoError(t, err)
		testutils.CompareJSON(t, tc.in, tc.out)

		err = cache.GetOrSet(ctx, p, tc.name, tc.out, func() (any, error) {
			getterCalls++
			return nil, errors.New("getter called on cache hit")
		})
		require.NoError(t, err)
		assert.Equal(t, 1, getterCalls)
	}

	keys, err := p.Keys(ctx, "*")
	require.NoError(t, err)
	names := make([]string, 0, len(tcases))
	for _, tc := range tcases {
		names = append(names, tc.name)
	}
	// keys are listed relative to the provider, as passed to Set
	assert.ElementsMatch(t, names, keys)
	keys, err = p.Keys(ctx, "strin?*")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"string", "strings"}, keys)

	p.CleanExpired(ctx)

	// With Redis we can't use NowFunc to override local time,
	// so have to sleep to expire
	for _, tc := range tcases {
		err = p.Set(ctx, tc.name, tc.in, time.Millisecond)
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
		// try expired
		err = p.Get(ctx, tc.name, tc.out)
		assert.True(t, cache.IsNotFoundError(err))
	}

	for _, tc := range tcases {
		err = p.Set(ctx, tc.name, tc.in, time.Millisecond)
		require.NoError(t, err)
	}
	time.Sleep(2 * time.Millisecond)
	p.CleanExpired(ctx)
	for _, tc := range tcases {
		// try expired
		err = p.Get(ctx, tc.name, tc.out)
		assert.True(t, cache.IsNotFoundError(err))
	}

	for _, tc := range tcases {
		err = p.Set(ctx, tc.name, tc.in, time.Minute)
		require.NoError(t, err)
		err = p.Delete(ctx, tc.name)
		require.NoError(t, err)
		// try deleted
		err = p.Get(ctx, tc.name, tc.out)
		assert.True(t, cache.IsNotFoundError(err))
	}
	// delete deleted
	for _, tc := range tcases {
		err = p.Delete(ctx, tc.name)
		require.NoError(t, err)
	}
	//never expires

	p = cache.NewProxyProvider("child", p)
	for _, tc := range tcases {
		err = p.Set(ctx, tc.name, tc.in, cache.KeepTTL)
		require.NoError(t, err)
		err = p.Get(ctx, tc.name, tc.out)
		require.NoError(t, err)
		testutils.CompareJSON(t, tc.in, tc.out)
	}

	p.CleanExpired(ctx)

	pubsubTest(t, p)
}

// pubsubTimeout bounds every wait in pubsubTest; a Redis round trip is
// milliseconds, so hitting it means a receive is stuck.
const pubsubTimeout = 5 * time.Second

// promptTimeout bounds a ReceiveMessage that must return without waiting
// for a message: after ctx is done or the subscription is closed.
const promptTimeout = time.Second

type recvResult struct {
	msg string
	err error
}

// receiveAsync runs one ReceiveMessage in a goroutine so the test can
// cancel or close while it is pending and assert from the test goroutine.
func receiveAsync(ctx context.Context, sub cache.Subscription) <-chan recvResult {
	res := make(chan recvResult, 1)
	go func() {
		msg, err := sub.ReceiveMessage(ctx)
		res <- recvResult{msg: msg, err: err}
	}()
	return res
}

func awaitResult(t *testing.T, res <-chan recvResult, timeout time.Duration) recvResult {
	t.Helper()
	select {
	case r := <-res:
		return r
	case <-time.After(timeout):
		require.FailNow(t, "ReceiveMessage did not return", "waited %s", timeout)
		return recvResult{}
	}
}

// goroutineStacks returns the stack dump of every goroutine.
func goroutineStacks() string {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// pubsubGoroutines counts the goroutines started by go-redis
// PubSub.Channel by their "created by" stack line; the memory provider
// starts none. The == 0 leak checks rely on TestProvider running
// sequentially: Go starts top-level t.Parallel tests only after it ends.
func pubsubGoroutines() int {
	return strings.Count(goroutineStacks(), "created by github.com/redis/go-redis/v9.(*channel).init")
}

// readerBlockedOnSend reports whether a go-redis message reader is blocked
// sending into a full subscriber channel: that send is the only blocking
// select in initMsgChan, while a socket read shows as IO wait.
func readerBlockedOnSend() bool {
	for _, g := range strings.Split(goroutineStacks(), "\n\n") {
		if strings.Contains(g, "[select") && strings.Contains(g, "go-redis/v9.(*channel).initMsgChan.func1") {
			return true
		}
	}
	return false
}

func pubsubTest(t *testing.T, p cache.Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	chanName := "test" + certutil.RandomString(4)

	t.Run("cancel", func(t *testing.T) {
		sub := p.Subscribe(ctx, chanName)
		defer func() {
			assert.NoError(t, sub.Close())
		}()

		// wait without publishing, then cancel: the receive returns promptly
		ctx2, cancel2 := context.WithCancel(ctx)
		res := receiveAsync(ctx2, sub)
		cancel2()
		r := awaitResult(t, res, promptTimeout)
		assert.ErrorIs(t, r.err, context.Canceled)
		assert.Empty(t, r.msg)

		// a receive that times out
		ctx3, cancel3 := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel3()
		r = awaitResult(t, receiveAsync(ctx3, sub), promptTimeout)
		assert.ErrorIs(t, r.err, context.DeadlineExceeded)

		// abandoned receives must not consume the next message (formerly P-041)
		require.NoError(t, p.Publish(ctx, chanName, "after-cancel"))
		r = awaitResult(t, receiveAsync(ctx, sub), pubsubTimeout)
		require.NoError(t, r.err)
		assert.Equal(t, "after-cancel", r.msg)
	})

	t.Run("close", func(t *testing.T) {
		sub := p.Subscribe(ctx, chanName)

		res := receiveAsync(ctx, sub)
		require.NoError(t, sub.Close())
		r := awaitResult(t, res, promptTimeout)
		assert.ErrorIs(t, r.err, cache.ErrClosed)

		// idempotent, and later receives fail the same way
		assert.NoError(t, sub.Close())
		_, err := sub.ReceiveMessage(ctx)
		assert.ErrorIs(t, err, cache.ErrClosed)

		// publishing to a closed subscriber is not an error
		assert.NoError(t, p.Publish(ctx, chanName, "nobody"))

		// a message buffered before Close is discarded (memory buffers
		// synchronously; for Redis the message may still be in flight)
		sub = p.Subscribe(ctx, chanName)
		require.NoError(t, p.Publish(ctx, chanName, "buffered"))
		require.NoError(t, sub.Close())
		_, err = sub.ReceiveMessage(ctx)
		assert.ErrorIs(t, err, cache.ErrClosed)
	})

	t.Run("broadcast", func(t *testing.T) {
		sub1 := p.Subscribe(ctx, chanName)
		sub2 := p.Subscribe(ctx, chanName)
		defer func() {
			assert.NoError(t, sub1.Close())
			assert.NoError(t, sub2.Close())
		}()

		// Subscribe has returned, so the publish reaches both subscribers
		require.NoError(t, p.Publish(ctx, chanName, "val1"))
		require.NoError(t, p.Publish(ctx, chanName, "val2"))

		for _, sub := range []cache.Subscription{sub1, sub2} {
			r := awaitResult(t, receiveAsync(ctx, sub), pubsubTimeout)
			require.NoError(t, r.err)
			assert.Equal(t, "val1", r.msg)
			r = awaitResult(t, receiveAsync(ctx, sub), pubsubTimeout)
			require.NoError(t, r.err)
			assert.Equal(t, "val2", r.msg)
		}

		if !p.IsLocal() {
			// the marker in pubsubGoroutines still matches go-redis
			assert.Positive(t, pubsubGoroutines())
		}
	})

	// every subscription is closed: no reader or health-check goroutine remains
	assert.Eventually(t, func() bool {
		return pubsubGoroutines() == 0
	}, pubsubTimeout, 20*time.Millisecond, "go-redis pub/sub goroutines leaked")
}

func TestRedisSubscribeUnreachable(t *testing.T) {
	t.Parallel()

	p, err := cache.NewRedisProvider(cache.RedisConfig{
		Server: "redis://127.0.0.1:1",
	}, "unreachable")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, p.Close())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), pubsubTimeout)
	defer cancel()

	sub := p.Subscribe(ctx, "chan")
	require.NotNil(t, sub)
	_, err = sub.ReceiveMessage(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to subscribe to channel chan")
	// the error is stable and Close holds nothing
	_, err2 := sub.ReceiveMessage(ctx)
	assert.EqualError(t, err2, err.Error())
	assert.NoError(t, sub.Close())
	assert.NoError(t, sub.Close())

	err = p.Publish(ctx, "chan", "msg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to publish to channel chan")
}

// silentRedis is a fake Redis that answers every command with an error,
// which go-redis tolerates for HELLO and CLIENT SETINFO, except SUBSCRIBE,
// which it never confirms. A non-nil onCommand is called with the upper
// case name of every command received, before the reply; it may block to
// hold the reply.
func silentRedis(t *testing.T, onCommand func(name string)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, ln.Close())
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSilentRedis(conn, onCommand)
		}
	}()
	return ln.Addr().String()
}

func serveSilentRedis(conn net.Conn, onCommand func(name string)) {
	defer func() {
		_ = conn.Close()
	}()
	rd := bufio.NewReader(conn)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		if !strings.HasPrefix(line, "*") {
			continue
		}
		argc, err := strconv.Atoi(strings.TrimSpace(line[1:]))
		if err != nil {
			return
		}
		args := make([]string, 0, argc)
		for range argc {
			// bulk string: $<len> line, then the data line
			if _, err := rd.ReadString('\n'); err != nil {
				return
			}
			arg, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			args = append(args, strings.TrimSpace(arg))
		}
		if len(args) == 0 {
			continue
		}
		name := strings.ToUpper(args[0])
		if onCommand != nil {
			onCommand(name)
		}
		if name == "SUBSCRIBE" {
			continue
		}
		if _, err := conn.Write([]byte("-ERR unknown command\r\n")); err != nil {
			return
		}
	}
}

// awaitSubscription returns the result of an asynchronous Subscribe or
// fails the test when it takes longer than timeout.
func awaitSubscription(t *testing.T, res <-chan cache.Subscription, timeout time.Duration) cache.Subscription {
	t.Helper()
	select {
	case sub := <-res:
		return sub
	case <-time.After(timeout):
		require.FailNow(t, "Subscribe did not return", "waited %s", timeout)
		return nil
	}
}

func TestRedisSubscribeContext(t *testing.T) {
	t.Parallel()

	p, err := cache.NewRedisProvider(cache.RedisConfig{
		Server: "redis://" + silentRedis(t, nil),
	}, "silent")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, p.Close())
	}()

	subscribeAsync := func(ctx context.Context) <-chan cache.Subscription {
		res := make(chan cache.Subscription, 1)
		go func() {
			res <- p.Subscribe(ctx, "chan")
		}()
		return res
	}

	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		res := subscribeAsync(ctx)
		time.Sleep(50 * time.Millisecond)
		cancel()
		sub := awaitSubscription(t, res, pubsubTimeout)
		_, err := sub.ReceiveMessage(context.Background())
		assert.ErrorIs(t, err, context.Canceled)
		assert.Contains(t, err.Error(), "failed to subscribe to channel chan")
		assert.NoError(t, sub.Close())
	})

	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		sub := awaitSubscription(t, subscribeAsync(ctx), pubsubTimeout)
		_, err := sub.ReceiveMessage(context.Background())
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.NoError(t, sub.Close())
	})
}

// TestRedisSubscribeDuringClose closes the provider while Subscribe waits
// for a confirmation that the fake server never sends: Close breaks the
// connection, and the failure is reported as ErrClosed, not as the
// resulting connection error.
func TestRedisSubscribeDuringClose(t *testing.T) {
	t.Parallel()

	subscribed := make(chan struct{}, 1)
	p, err := cache.NewRedisProvider(cache.RedisConfig{
		Server: "redis://" + silentRedis(t, func(name string) {
			if name == "SUBSCRIBE" {
				select {
				case subscribed <- struct{}{}:
				default:
				}
			}
		}),
	}, "silent-close")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), pubsubTimeout)
	defer cancel()
	res := make(chan cache.Subscription, 1)
	go func() {
		res <- p.Subscribe(ctx, "chan")
	}()
	select {
	case <-subscribed:
	case <-time.After(pubsubTimeout):
		require.FailNow(t, "SUBSCRIBE did not reach the server", "waited %s", pubsubTimeout)
	}
	require.NoError(t, p.Close())

	sub := awaitSubscription(t, res, pubsubTimeout)
	_, err = sub.ReceiveMessage(ctx)
	require.ErrorIs(t, err, cache.ErrClosed)
	assert.Contains(t, err.Error(), "failed to subscribe to channel chan: provider closed")
	assert.NoError(t, sub.Close())
}

// TestRedisSubscribeCloseDuringSetup closes the provider while go-redis
// still sets up the subscription connection (the fake server holds its
// HELLO reply); the client does not track that connection yet, so Close
// cannot close it, and Subscribe must still report ErrClosed at once
// instead of waiting for the confirmation.
func TestRedisSubscribeCloseDuringSetup(t *testing.T) {
	t.Parallel()

	hello := make(chan struct{})
	release := make(chan struct{})
	releaseHello := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseHello)
	var holdOnce sync.Once
	p, err := cache.NewRedisProvider(cache.RedisConfig{
		Server: "redis://" + silentRedis(t, func(name string) {
			if name == "HELLO" {
				holdOnce.Do(func() {
					close(hello)
					<-release
				})
			}
		}),
	}, "silent-setup")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), pubsubTimeout)
	defer cancel()
	res := make(chan cache.Subscription, 1)
	go func() {
		res <- p.Subscribe(ctx, "chan")
	}()
	select {
	case <-hello:
	case <-time.After(pubsubTimeout):
		require.FailNow(t, "HELLO did not reach the server", "waited %s", pubsubTimeout)
	}
	require.NoError(t, p.Close())
	releaseHello()

	// the confirmation wait would last until ctx expires
	sub := awaitSubscription(t, res, promptTimeout)
	_, err = sub.ReceiveMessage(ctx)
	require.ErrorIs(t, err, cache.ErrClosed)
	assert.Contains(t, err.Error(), "failed to subscribe to channel chan: provider closed")
	assert.NoError(t, sub.Close())
}

func TestIsNotFoundError(t *testing.T) {
	err := cache.ErrNotFound
	assert.True(t, cache.IsNotFoundError(err))
	assert.True(t, cache.IsNotFoundError(errors.WithMessage(err, "wrapped")))
	assert.True(t, cache.IsNotFoundError(errors.Wrap(err, "wrapped")))
	assert.True(t, cache.IsNotFoundError(errors.WithStack(err)))
	assert.True(t, cache.IsNotFoundError(errors.New("key not found")))
	assert.False(t, cache.IsNotFoundError(errors.New("invalid key")))
}
