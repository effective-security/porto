package cache_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/docker/docker/api/types/container"
	"github.com/effective-security/porto/pkg/cache"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	rediscon "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestProvider(t *testing.T) {
	ctx := context.Background()
	redisContainer, err := rediscon.Run(ctx, "docker.io/bitnami/redis:7.2",
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

	mem := cache.NewMemoryProvider(root)
	defer func() {
		assert.NoError(t, mem.Close())
	}()
	assert.True(t, mem.IsLocal())

	t.Run("memory", func(t *testing.T) {
		provTest(t, mem, root)
	})

	t.Run("proxy", func(t *testing.T) {
		pr := cache.NewProxyProvider("subkey", mem)
		defer func() {
			assert.NoError(t, pr.Close())
		}()
		assert.True(t, pr.IsLocal())
		provTest(t, pr, root)
	})
}

func provTest(t *testing.T, p cache.Provider, root string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	defer func() {
		// let's not polute redis
		for _, tc := range tcases {
			_ = p.Delete(ctx, tc.name)
		}
	}()

	for _, tc := range tcases {
		err = cache.GetOrSet(ctx, p, tc.name, tc.out, func() (any, error) {
			return &tc.in, nil
		})
		require.NoError(t, err)
		testutils.CompareJSON(t, tc.in, tc.out)

		err = p.Set(ctx, tc.name, tc.in, time.Hour)
		require.NoError(t, err)
		err = p.Get(ctx, tc.name, tc.out)
		require.NoError(t, err)
		testutils.CompareJSON(t, tc.in, tc.out)
	}

	keys, err := p.Keys(ctx, "*")
	require.NoError(t, err)
	assert.Len(t, keys, len(tcases))

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

	// test channel
	chanName := "test" + certutil.RandomString(4)

	t.Run("cancel", func(t *testing.T) {
		ctx2, cancel := context.WithTimeout(ctx, 50*time.Millisecond)

		sub := p.Subscribe(ctx, chanName)
		defer func() {
			assert.NoError(t, sub.Close())
		}()

		var wg sync.WaitGroup
		wg.Add(1)

		// wait without publishing
		go func() {
			defer wg.Done()
			_, err := sub.ReceiveMessage(ctx2)
			assert.Error(t, err, "context canceled")
		}()
		cancel()
		cerr := ctx2.Err()
		assert.Error(t, cerr)
		wg.Wait()
	})

	sub1 := p.Subscribe(ctx, chanName)
	sub2 := p.Subscribe(ctx, chanName)

	defer func() {
		assert.NoError(t, sub1.Close())
		assert.NoError(t, sub2.Close())
	}()

	ctx2, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		msg, err := sub1.ReceiveMessage(ctx2)
		require.NoError(t, err)
		assert.Equal(t, "val1", msg)
	}()

	go func() {
		defer wg.Done()
		msg, err := sub2.ReceiveMessage(ctx2)
		require.NoError(t, err)
		assert.Equal(t, "val1", msg)
	}()

	err = p.Publish(ctx, chanName, "val1")
	require.NoError(t, err)

	wg.Wait()
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
