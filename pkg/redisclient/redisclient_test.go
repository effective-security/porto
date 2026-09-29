package redisclient_test

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/redisclient"
	"github.com/effective-security/xlog"
	"github.com/moby/moby/api/types/container"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	rediscon "github.com/testcontainers/testcontainers-go/modules/redis"
)

func Test_Redis(t *testing.T) {
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

	host, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	rcfg := &redisclient.Config{
		Server:   host,
		Password: "redis",
	}
	rootclient, err := redisclient.New(rcfg)
	require.NoError(t, err)

	defer rootclient.Close()

	client := rootclient.WithPrefix("/test")

	err = client.Ping(ctx)
	require.NoError(t, err)

	assert.Equal(t, "/test", client.Key(""))
	assert.Equal(t, "/test/test_key", client.Key("test_key"))
	assert.Equal(t, "/test/test_key", client.Key("/test_key"))
	assert.Equal(t, "/test/test_key", client.Key("/test_key/"))
	// ".." cannot leave the prefix (formerly P-044)
	assert.Equal(t, "/test/other/x", client.Key("../other/x"))
	assert.Equal(t, "/test/x", client.Key("a/../../x"))
	assert.Equal(t, "/test", client.Key(".."))
	assert.Equal(t, "", client.SubKey(client.Key("")))
	assert.Equal(t, "a/b", client.SubKey(client.Key("/a//b/")))
	assert.Equal(t, "../x", rootclient.Key("../x"), "no prefix: key unchanged")
	nested := rootclient.WithPrefix(" /a//b/../c/ ")
	assert.Equal(t, "/a/c/k", nested.Key("k"))
	assert.Equal(t, "k", nested.SubKey(nested.Key("k")))
	assert.Equal(t, "/k", rootclient.WithPrefix("a/..").Key("k"))

	t.Run("string", func(t *testing.T) {
		ok, err := client.Exists(ctx, "test_key_str")
		require.NoError(t, err)
		assert.False(t, ok)

		// Set a key-value pair in Redis
		err = client.Set(ctx, "test_key_str", "test_value", time.Hour)
		require.NoError(t, err)

		exp, err := client.TTL(ctx, "test_key_str")
		require.NoError(t, err)
		assert.Equal(t, exp, time.Hour)

		client.Expire(ctx, "test_key_str", time.Second*10)
		exp, err = client.TTL(ctx, "test_key_str")
		require.NoError(t, err)
		assert.Equal(t, exp, time.Second*10)

		var strval string
		err = client.Get(ctx, "test_key_str", &strval)
		require.NoError(t, err)
		assert.Equal(t, "test_value", strval)

		ok, err = client.Exists(ctx, "test_key_str")
		require.NoError(t, err)
		assert.True(t, ok)

		list, err := client.Keys(ctx, "test_*")
		require.NoError(t, err)
		assert.Equal(t, []string{"test_key_str"}, list)

		list, err = client.ScanKeys(ctx, "test_*", 10)
		require.NoError(t, err)
		assert.Equal(t, []string{"test_key_str"}, list)

		err = client.Del(ctx, "test_key_str")
		require.NoError(t, err)
		ok, err = client.Exists(ctx, "test_key_str")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("sbytestring", func(t *testing.T) {
		// Set a key-value pair in Redis
		err = client.Set(ctx, "test_key_bytes", []byte("test_value"), 0)
		require.NoError(t, err)

		var bval []byte
		err = client.Get(ctx, "test_key_bytes", &bval)
		require.NoError(t, err)
		assert.Equal(t, []byte("test_value"), bval)

		err = client.Del(ctx, "test_key_bytes")
		require.NoError(t, err)
		ok, err := client.Exists(ctx, "test_key_bytes")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("obj", func(t *testing.T) {
		// Set a key-value pair in Redis
		err = client.Set(ctx, "test_key_obj", rcfg, 0)
		require.NoError(t, err)

		var obj redisclient.Config
		err = client.Get(ctx, "test_key_obj", &obj)
		require.NoError(t, err)
		assert.Equal(t, rcfg, &obj)

		err = client.Del(ctx, "test_key_obj")
		require.NoError(t, err)
		ok, err := client.Exists(ctx, "test_key_obj")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("List", func(t *testing.T) {
		err = client.LPush(ctx, "test_list", "value1", "value2", "value3")
		require.NoError(t, err)

		err = client.RPush(ctx, "test_list", "Rvalue1", "Rvalue2", "Rvalue3")
		require.NoError(t, err)

		list, err := client.LRange(ctx, "test_list", 0, -1)
		require.NoError(t, err)
		assert.Equal(t, []string{"value3", "value2", "value1", "Rvalue1", "Rvalue2", "Rvalue3"}, list)

		val, err := client.LPop(ctx, "test_list")
		require.NoError(t, err)
		assert.Equal(t, "value3", val)

		val, err = client.RPop(ctx, "test_list")
		require.NoError(t, err)
		assert.Equal(t, "Rvalue3", val)

		list, err = client.LRange(ctx, "test_list", 0, -1)
		require.NoError(t, err)
		assert.Equal(t, []string{"value2", "value1", "Rvalue1", "Rvalue2"}, list)

		err = client.LTrim(ctx, "test_list", 1, 3)
		require.NoError(t, err)

		list, err = client.LRange(ctx, "test_list", 0, -1)
		require.NoError(t, err)
		assert.Equal(t, []string{"value1", "Rvalue1", "Rvalue2"}, list)

		err = client.Del(ctx, "test_list")
		require.NoError(t, err)
		ok, err := client.Exists(ctx, "test_list")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("Set", func(t *testing.T) {
		err = client.SAdd(ctx, "test_set", "value1", "value2", "value3")
		require.NoError(t, err)

		err = client.SAdd(ctx, "test_set", "value4")
		require.NoError(t, err)

		members, err := client.SMembers(ctx, "test_set")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"value1", "value2", "value3", "value4"}, members)

		err = client.SRem(ctx, "test_set", "value2")
		require.NoError(t, err)

		members, err = client.SMembers(ctx, "test_set")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"value1", "value3", "value4"}, members)

		size, err := client.SCard(ctx, "test_set")
		require.NoError(t, err)
		assert.Equal(t, int64(3), size)

		err = client.Del(ctx, "test_set")
		require.NoError(t, err)
		ok, err := client.Exists(ctx, "test_set")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("SetWithEviction", func(t *testing.T) {
		for i := 0; i < 12; i++ {
			err = client.SAddWithEviction(ctx, "gap_test_set", "gap_test_set_list", 10, fmt.Sprintf("v%d", i))
			require.NoError(t, err)
		}
		members, err := client.SMembers(ctx, "gap_test_set")
		require.NoError(t, err)
		assert.Len(t, members, 10)
		assert.Equal(t, []string{"v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11"}, members)

		list, err := client.LRange(ctx, "gap_test_set_list", 0, -1)
		require.NoError(t, err)
		assert.Len(t, list, 10)

		err = client.Del(ctx, "gap_test_set")
		require.NoError(t, err)
		err = client.Del(ctx, "gap_test_set_list")
		require.NoError(t, err)

		//
		err = client.Del(ctx, "test_set")
		require.NoError(t, err)
		err = client.Del(ctx, "test_set_list")
		require.NoError(t, err)
	})

	t.Run("Hash", func(t *testing.T) {
		err = client.HSet(ctx, "test_hash", "field1", "value1")
		require.NoError(t, err)

		err = client.HSetMany(ctx, "test_hash", map[string]any{"field2": "value2", "field3": "value3"})
		require.NoError(t, err)

		val, err := client.HGet(ctx, "test_hash", "field1")
		require.NoError(t, err)
		assert.Equal(t, "value1", val)

		val, err = client.HGet(ctx, "test_hash", "field2")
		require.NoError(t, err)
		assert.Equal(t, "value2", val)

		fields, err := client.HKeys(ctx, "test_hash")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"field1", "field2", "field3"}, fields)

		err = client.HDel(ctx, "test_hash", "field1")
		require.NoError(t, err)

		_, err = client.HGet(ctx, "test_hash", "field1")
		require.EqualError(t, err, "not found")

		err = client.Del(ctx, "test_hash")
		require.NoError(t, err)
		ok, err := client.Exists(ctx, "test_hash")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("HashWithEviction", func(t *testing.T) {
		for i := 0; i < 12; i++ {
			err = client.HSetWithEviction(ctx, "gap_test_hash", "gap_test_hash_list", 10, fmt.Sprintf("field%d", i), fmt.Sprintf("value%d", i))
			require.NoError(t, err)
		}
		fields, err := client.HKeys(ctx, "gap_test_hash")
		require.NoError(t, err)
		assert.Len(t, fields, 10)
		assert.Equal(t, []string{"field2", "field3", "field4", "field5", "field6", "field7", "field8", "field9", "field10", "field11"}, fields)

		list, err := client.LRange(ctx, "gap_test_hash_list", 0, -1)
		require.NoError(t, err)
		assert.Len(t, list, 10)

		err = client.Del(ctx, "gap_test_hash")
		require.NoError(t, err)
		err = client.Del(ctx, "gap_test_hash_list")
		require.NoError(t, err)

		err = client.Del(ctx, "test_hash")
		require.NoError(t, err)
		err = client.Del(ctx, "test_hash_list")
		require.NoError(t, err)
	})

	t.Run("Zset", func(t *testing.T) {
		for i := 0; i < 12; i++ {
			err = client.ZAdd(ctx, "test_zset", 1.0, fmt.Sprintf("value%d", i))
			require.NoError(t, err)
		}
		for i := 0; i < 12; i++ {
			for j := 0; j < i; j++ {
				err = client.ZIncrBy(ctx, "test_zset", 1.0, fmt.Sprintf("value%d", j))
				require.NoError(t, err)
			}
		}

		card, err := client.ZCard(ctx, "test_zset")
		require.NoError(t, err)
		assert.Equal(t, int64(12), card)

		// Get the top 3 elements
		members, err := client.ZRevRangeWithScores(ctx, "test_zset", 0, 2)
		require.NoError(t, err)
		assert.Equal(t, []redis.Z{
			{Score: 12.0, Member: "value0"},
			{Score: 11.0, Member: "value1"},
			{Score: 10.0, Member: "value2"},
		}, members)

		// Get the bottom 3 elements
		members, err = client.ZRevRangeWithScores(ctx, "test_zset", -3, -1)
		require.NoError(t, err)
		assert.Equal(t, []redis.Z{
			{Score: 3.0, Member: "value9"},
			{Score: 2.0, Member: "value10"},
			{Score: 1.0, Member: "value11"},
		}, members)

		// Keep the top 3 elements
		removed, err := client.ZRemRangeByRank(ctx, "test_zset", 0, -4)
		require.NoError(t, err)
		assert.Equal(t, int64(9), removed)

		card, err = client.ZCard(ctx, "test_zset")
		require.NoError(t, err)
		assert.Equal(t, int64(3), card)

		err = client.Del(ctx, "test_zset")
		require.NoError(t, err)
	})

	t.Run("SetWithEvictionReAdd", func(t *testing.T) {
		const set, list = "evict_readd_set", "evict_readd_list"
		t.Cleanup(func() { cleanup(ctx, t, client, set, list) })
		// re-adding "a" keeps its position, so "a" is evicted first and the
		// set keeps the three newest distinct members (formerly P-063)
		for _, m := range []string{"a", "b", "c", "a", "d"} {
			require.NoError(t, client.SAddWithEviction(ctx, set, list, 3, m))
		}
		members, err := client.SMembers(ctx, set)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"b", "c", "d"}, members)
		order, err := client.LRange(ctx, list, 0, -1)
		require.NoError(t, err)
		assert.Equal(t, []string{"b", "c", "d"}, order)

		// a lower limit evicts down to it in one call
		require.NoError(t, client.SAddWithEviction(ctx, set, list, 1, "e"))
		members, err = client.SMembers(ctx, set)
		require.NoError(t, err)
		assert.Equal(t, []string{"e"}, members)
		order, err = client.LRange(ctx, list, 0, -1)
		require.NoError(t, err)
		assert.Equal(t, []string{"e"}, order)
	})

	t.Run("SetWithEvictionStaleEntries", func(t *testing.T) {
		const set, list = "evict_stale_set", "evict_stale_list"
		t.Cleanup(func() { cleanup(ctx, t, client, set, list) })
		for _, m := range []string{"a", "b", "c"} {
			require.NoError(t, client.SAddWithEviction(ctx, set, list, 3, m))
		}
		// "a" removed from the set only, and a duplicate "b" as written by
		// earlier versions: neither stale entry may evict the re-added member
		require.NoError(t, client.SRem(ctx, set, "a"))
		require.NoError(t, client.RPush(ctx, list, "b"))
		require.NoError(t, client.SRem(ctx, set, "b"))

		require.NoError(t, client.SAddWithEviction(ctx, set, list, 3, "a"))
		require.NoError(t, client.SAddWithEviction(ctx, set, list, 3, "b"))
		members, err := client.SMembers(ctx, set)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"a", "b", "c"}, members)
		order, err := client.LRange(ctx, list, 0, -1)
		require.NoError(t, err)
		assert.Equal(t, []string{"c", "a", "b"}, order)

		// the same for a hash whose field was deleted directly
		const hash, hlist = "evict_stale_hash", "evict_stale_hlist"
		t.Cleanup(func() { cleanup(ctx, t, client, hash, hlist) })
		for _, f := range []string{"f1", "f2"} {
			require.NoError(t, client.HSetWithEviction(ctx, hash, hlist, 2, f, "v"))
		}
		require.NoError(t, client.HDel(ctx, hash, "f1"))
		require.NoError(t, client.HSetWithEviction(ctx, hash, hlist, 2, "f1", "v1"))
		vals, err := client.HGetAll(ctx, hash)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"f1": "v1", "f2": "v"}, vals)
		order, err = client.LRange(ctx, hlist, 0, -1)
		require.NoError(t, err)
		assert.Equal(t, []string{"f2", "f1"}, order)
	})

	t.Run("SetWithEvictionErrors", func(t *testing.T) {
		const set, list, str = "evict_err_set", "evict_err_list", "evict_err_str"
		t.Cleanup(func() { cleanup(ctx, t, client, set, list, str) })

		err := client.SAddWithEviction(ctx, set, list, 0, "m")
		require.EqualError(t, err, "eviction limit for evict_err_set must be positive: 0")
		err = client.SAddWithEviction(ctx, set, "/"+set+"/", 3, "m")
		require.EqualError(t, err, "eviction list key must differ from evict_err_set")

		// a key of the wrong type fails before anything is written
		require.NoError(t, client.Set(ctx, str, "x", time.Minute))
		err = client.SAddWithEviction(ctx, set, str, 3, "m")
		require.ErrorContains(t, err, "unable to add member to bounded set evict_err_set")
		require.ErrorContains(t, err, "WRONGTYPE")
		ok, err := client.Exists(ctx, set)
		require.NoError(t, err)
		assert.False(t, ok, "set written before the list type error")

		err = client.SAddWithEviction(ctx, str, list, 3, "m")
		require.ErrorContains(t, err, "WRONGTYPE")
		ok, err = client.Exists(ctx, list)
		require.NoError(t, err)
		assert.False(t, ok, "list written before the set type error")
	})

	t.Run("HashWithEvictionUpdate", func(t *testing.T) {
		const hash, list = "evict_upd_hash", "evict_upd_list"
		t.Cleanup(func() { cleanup(ctx, t, client, hash, list) })
		// updating f1 keeps its position, so f1 is evicted first
		for _, kv := range [][2]string{{"f1", "v1"}, {"f2", "v2"}, {"f1", "v1b"}, {"f3", "v3"}} {
			require.NoError(t, client.HSetWithEviction(ctx, hash, list, 2, kv[0], kv[1]))
		}
		vals, err := client.HGetAll(ctx, hash)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"f2": "v2", "f3": "v3"}, vals)
		order, err := client.LRange(ctx, list, 0, -1)
		require.NoError(t, err)
		assert.Equal(t, []string{"f2", "f3"}, order)

		// values are encoded as by HSet
		require.NoError(t, client.HSetWithEviction(ctx, hash, list, 2, "f4", 42))
		val, err := client.HGet(ctx, hash, "f4")
		require.NoError(t, err)
		assert.Equal(t, "42", val)
	})

	t.Run("HashWithEvictionErrors", func(t *testing.T) {
		const hash, list, str = "evict_err_hash", "evict_err_hlist", "evict_err_hstr"
		t.Cleanup(func() { cleanup(ctx, t, client, hash, list, str) })

		err := client.HSetWithEviction(ctx, hash, list, -1, "f", "v")
		require.EqualError(t, err, "eviction limit for evict_err_hash must be positive: -1")
		err = client.HSetWithEviction(ctx, hash, hash, 3, "f", "v")
		require.EqualError(t, err, "eviction list key must differ from evict_err_hash")

		require.NoError(t, client.Set(ctx, str, "x", time.Minute))
		err = client.HSetWithEviction(ctx, hash, str, 3, "f", "v")
		require.ErrorContains(t, err, "unable to set field f in bounded hash evict_err_hash")
		require.ErrorContains(t, err, "WRONGTYPE")
		ok, err := client.Exists(ctx, hash)
		require.NoError(t, err)
		assert.False(t, ok, "hash written before the list type error")
	})

	t.Run("KeyNamespace", func(t *testing.T) {
		other := rootclient.WithPrefix("other")
		t.Cleanup(func() { cleanup(ctx, t, client, "other/x") })

		// a ".." key stays under the client prefix (formerly P-044)
		require.NoError(t, client.Set(ctx, "../other/x", "v", time.Minute))
		ok, err := other.Exists(ctx, "x")
		require.NoError(t, err)
		assert.False(t, ok, "key escaped into the sibling prefix")
		var val string
		require.NoError(t, client.Get(ctx, "other/x", &val))
		assert.Equal(t, "v", val)

		// glob metacharacters in the prefix match literally: "/m*[1]/*"
		// unescaped would also match the sibling "/mX1/"
		meta := rootclient.WithPrefix("m*[1]")
		sibling := rootclient.WithPrefix("mX1")
		t.Cleanup(func() {
			cleanup(ctx, t, meta, "k1", "k2")
			cleanup(ctx, t, sibling, "k3")
		})
		require.NoError(t, meta.Set(ctx, "k1", "v", time.Minute))
		require.NoError(t, meta.Set(ctx, "k2", "v", time.Minute))
		require.NoError(t, sibling.Set(ctx, "k3", "v", time.Minute))

		keys, err := meta.Keys(ctx, "*")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"k1", "k2"}, keys)
		keys, err = meta.ScanKeys(ctx, "k*", 0)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"k1", "k2"}, keys)
		keys, err = meta.Keys(ctx, "../*1")
		require.NoError(t, err)
		assert.Equal(t, []string{"k1"}, keys)
		keys, err = sibling.Keys(ctx, "*")
		require.NoError(t, err)
		assert.Equal(t, []string{"k3"}, keys)
	})

	t.Run("DistributedLock", func(t *testing.T) {
		token, remaining, err := client.TryLock(ctx, "test_lock", 5*time.Second)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Equal(t, time.Duration(0), remaining)

		locked, err := client.IsLocked(ctx, "test_lock")
		require.NoError(t, err)
		assert.True(t, locked)

		// held: no token, remaining time of the holder
		token2, remaining2, err := client.TryLock(ctx, "test_lock", 5*time.Second)
		require.NoError(t, err)
		assert.Empty(t, token2)
		assert.Greater(t, remaining2, time.Duration(0))
		assert.LessOrEqual(t, remaining2, 5*time.Second)

		// another owner's token does not release the lock (formerly P-047)
		released, err := client.ReleaseLock(ctx, "test_lock", "not-the-owner")
		require.NoError(t, err)
		assert.False(t, released)
		locked, err = client.IsLocked(ctx, "test_lock")
		require.NoError(t, err)
		assert.True(t, locked)

		released, err = client.ReleaseLock(ctx, "test_lock", token)
		require.NoError(t, err)
		assert.True(t, released)
		locked, err = client.IsLocked(ctx, "test_lock")
		require.NoError(t, err)
		assert.False(t, locked)

		// released already
		released, err = client.ReleaseLock(ctx, "test_lock", token)
		require.NoError(t, err)
		assert.False(t, released)

		// a new acquisition gets a new token
		token3, _, err := client.TryLock(ctx, "test_lock", 5*time.Second)
		require.NoError(t, err)
		assert.NotEmpty(t, token3)
		assert.NotEqual(t, token, token3)
		released, err = client.ReleaseLock(ctx, "test_lock", token3)
		require.NoError(t, err)
		assert.True(t, released)
	})

	t.Run("LockExpiredOwner", func(t *testing.T) {
		// the first owner's lock expires and a second owner acquires it;
		// the first owner's late release leaves it alone (formerly P-047)
		first, _, err := client.TryLock(ctx, "expire_lock", 100*time.Millisecond)
		require.NoError(t, err)
		require.NotEmpty(t, first)
		require.Eventually(t, func() bool {
			locked, err := client.IsLocked(ctx, "expire_lock")
			return err == nil && !locked
		}, 5*time.Second, 20*time.Millisecond)

		second, _, err := client.TryLock(ctx, "expire_lock", 5*time.Second)
		require.NoError(t, err)
		require.NotEmpty(t, second)

		released, err := client.ReleaseLock(ctx, "expire_lock", first)
		require.NoError(t, err)
		assert.False(t, released)
		locked, err := client.IsLocked(ctx, "expire_lock")
		require.NoError(t, err)
		assert.True(t, locked)

		released, err = client.ReleaseLock(ctx, "expire_lock", second)
		require.NoError(t, err)
		assert.True(t, released)
	})

	t.Run("LockArguments", func(t *testing.T) {
		for _, timeout := range []time.Duration{0, -time.Second, 500 * time.Microsecond} {
			token, remaining, err := client.TryLock(ctx, "arg_lock", timeout)
			require.EqualError(t, err, fmt.Sprintf("lock timeout for key arg_lock must be at least 1ms: %s", timeout))
			assert.Empty(t, token)
			assert.Equal(t, time.Duration(0), remaining)
		}
		locked, err := client.IsLocked(ctx, "arg_lock")
		require.NoError(t, err)
		assert.False(t, locked)

		released, err := client.ReleaseLock(ctx, "arg_lock", "")
		require.EqualError(t, err, "empty lock token for key: arg_lock")
		assert.False(t, released)
	})

	t.Run("CoordinationKeyNamespace", func(t *testing.T) {
		// ".." cannot turn a lock or rate-limit key into a data key
		require.NoError(t, client.Set(ctx, "victim", "v", time.Minute))
		t.Cleanup(func() { cleanup(ctx, t, client, "victim") })
		const escaping = "x/../../victim"

		token, _, err := client.TryLock(ctx, escaping, time.Second)
		require.EqualError(t, err, `invalid key "x/../../victim": leaves the "lock" namespace`)
		assert.Empty(t, token)
		locked, err := client.IsLocked(ctx, escaping)
		require.EqualError(t, err, `invalid key "x/../../victim": leaves the "lock" namespace`)
		assert.False(t, locked)
		released, err := client.ReleaseLock(ctx, escaping, "token")
		require.EqualError(t, err, `invalid key "x/../../victim": leaves the "lock" namespace`)
		assert.False(t, released)

		allowed, _, err := client.TryAcquireRateLimit(ctx, escaping, time.Second)
		require.EqualError(t, err, `invalid key "x/../../victim": leaves the "ratelimit" namespace`)
		assert.False(t, allowed)
		remaining, err := client.GetRateLimitRemainingTime(ctx, escaping)
		require.EqualError(t, err, `invalid key "x/../../victim": leaves the "ratelimit" namespace`)
		assert.Equal(t, time.Duration(0), remaining)

		var val string
		require.NoError(t, client.Get(ctx, "victim", &val))
		assert.Equal(t, "v", val)

		// without a prefix the key is not cleaned and cannot leave
		token, _, err = rootclient.TryLock(ctx, escaping, time.Second)
		require.NoError(t, err)
		require.NotEmpty(t, token)
		exists, err := rootclient.Exists(ctx, "lock:"+escaping)
		require.NoError(t, err)
		assert.True(t, exists)
		released, err = rootclient.ReleaseLock(ctx, escaping, token)
		require.NoError(t, err)
		assert.True(t, released)

		// ".." inside the lock namespace is fine
		token, _, err = client.TryLock(ctx, "a/b/../c", time.Second)
		require.NoError(t, err)
		require.NotEmpty(t, token)
		locked, err = client.IsLocked(ctx, "a/c")
		require.NoError(t, err)
		assert.True(t, locked)
		released, err = client.ReleaseLock(ctx, "a/c", token)
		require.NoError(t, err)
		assert.True(t, released)
	})

	t.Run("RateLimiter", func(t *testing.T) {
		const window = time.Second
		allowed, remaining, err := client.TryAcquireRateLimit(ctx, "test_rate_limit", window)
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, time.Duration(0), remaining)

		allowed, remaining, err = client.TryAcquireRateLimit(ctx, "test_rate_limit", window)
		require.NoError(t, err)
		assert.False(t, allowed)
		assert.Greater(t, remaining, time.Duration(0))
		assert.LessOrEqual(t, remaining, window)

		remaining, err = client.GetRateLimitRemainingTime(ctx, "test_rate_limit")
		require.NoError(t, err)
		assert.Greater(t, remaining, time.Duration(0))
		assert.LessOrEqual(t, remaining, window)

		// the window ends on the server
		require.Eventually(t, func() bool {
			remaining, err := client.GetRateLimitRemainingTime(ctx, "test_rate_limit")
			return err == nil && remaining == 0
		}, 5*time.Second, 20*time.Millisecond)
		allowed, remaining, err = client.TryAcquireRateLimit(ctx, "test_rate_limit", window)
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, time.Duration(0), remaining)

		remaining, err = client.GetRateLimitRemainingTime(ctx, "non_existent_rate_limit")
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), remaining)

		for _, w := range []time.Duration{0, -time.Second, time.Microsecond} {
			allowed, remaining, err = client.TryAcquireRateLimit(ctx, "arg_rate_limit", w)
			require.EqualError(t, err, fmt.Sprintf("rate limit window for key arg_rate_limit must be at least 1ms: %s", w))
			assert.False(t, allowed)
			assert.Equal(t, time.Duration(0), remaining)
		}
	})

	t.Run("RateLimiterPolling", func(t *testing.T) {
		// callers polling faster than the window, from several goroutines,
		// are allowed once per window: denied polls do not extend the window
		// and two callers never win the same window (formerly P-043)
		const (
			window  = 200 * time.Millisecond
			pollers = 4
			polling = 1100 * time.Millisecond
		)
		// call is the client-clock span of an allowed call; the server
		// started its window somewhere inside it
		type call struct{ start, end time.Time }
		var (
			mu      sync.Mutex
			allowed []call
			errs    = make(chan error, pollers)
			wg      sync.WaitGroup
		)
		deadline := time.Now().Add(polling)
		for range pollers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(deadline) {
					start := time.Now()
					ok, _, err := client.TryAcquireRateLimit(ctx, "polling_rate_limit", window)
					if err != nil {
						errs <- err
						return
					}
					if ok {
						mu.Lock()
						allowed = append(allowed, call{start: start, end: time.Now()})
						mu.Unlock()
					}
					time.Sleep(10 * time.Millisecond)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}

		slices.SortFunc(allowed, func(a, b call) int { return a.start.Compare(b.start) })
		// about polling/window windows start; before the fix only the first did
		assert.GreaterOrEqual(t, len(allowed), 3)
		for i := 1; i < len(allowed); i++ {
			// windows start at least window apart on the server and each
			// start lies inside its call's span; the calls may have been
			// served in either order
			prev, cur := allowed[i-1], allowed[i]
			assert.GreaterOrEqual(t, max(cur.end.Sub(prev.start), prev.end.Sub(cur.start)), window,
				"two calls allowed within one window")
		}
	})

	t.Run("RateLimiterLegacyWindow", func(t *testing.T) {
		// a window written by an earlier version (a sorted set) is honored
		key := client.Key("ratelimit:legacy_rate_limit")
		require.NoError(t, client.Client.ZAdd(ctx, key, redis.Z{Score: 1, Member: 1}).Err())
		require.NoError(t, client.Client.Expire(ctx, key, 5*time.Second).Err())
		t.Cleanup(func() { cleanup(ctx, t, client, "ratelimit:legacy_rate_limit") })

		allowed, remaining, err := client.TryAcquireRateLimit(ctx, "legacy_rate_limit", time.Second)
		require.NoError(t, err)
		assert.False(t, allowed)
		assert.Greater(t, remaining, time.Second)
		assert.LessOrEqual(t, remaining, 5*time.Second)
	})

	t.Run("ConcurrentLocking", func(t *testing.T) {
		const numGoroutines = 10
		type result struct {
			token string
			err   error
		}
		results := make(chan result, numGoroutines)
		for range numGoroutines {
			go func() {
				token, _, err := client.TryLock(ctx, "concurrent_lock", 5*time.Second)
				results <- result{token: token, err: err}
			}()
		}

		var tokens []string
		for range numGoroutines {
			r := <-results
			require.NoError(t, r.err)
			if r.token != "" {
				tokens = append(tokens, r.token)
			}
		}
		// only one acquired the lock
		require.Len(t, tokens, 1)

		released, err := client.ReleaseLock(ctx, "concurrent_lock", tokens[0])
		require.NoError(t, err)
		assert.True(t, released)
	})

	t.Run("ConcurrentRateLimiting", func(t *testing.T) {
		const numGoroutines = 10
		type result struct {
			allowed bool
			err     error
		}
		results := make(chan result, numGoroutines)
		for range numGoroutines {
			go func() {
				allowed, _, err := client.TryAcquireRateLimit(ctx, "concurrent_rate_limit", 5*time.Second)
				results <- result{allowed: allowed, err: err}
			}()
		}

		allowedCount := 0
		for range numGoroutines {
			r := <-results
			require.NoError(t, r.err)
			if r.allowed {
				allowedCount++
			}
		}
		// only one is allowed
		assert.Equal(t, 1, allowedCount)
	})

	t.Run("KeyPrefixing", func(t *testing.T) {
		token, _, err := client.TryLock(ctx, "prefix_test", 5*time.Second)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// the lock key is prefixed
		exists, err := client.Exists(ctx, "lock:prefix_test")
		require.NoError(t, err)
		assert.True(t, exists)
		exists, err = rootclient.Exists(ctx, "/test/lock:prefix_test")
		require.NoError(t, err)
		assert.True(t, exists)

		allowed, _, err := client.TryAcquireRateLimit(ctx, "prefix_rate_test", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, allowed)

		// the rate limit key is prefixed
		exists, err = client.Exists(ctx, "ratelimit:prefix_rate_test")
		require.NoError(t, err)
		assert.True(t, exists)

		released, err := client.ReleaseLock(ctx, "prefix_test", token)
		require.NoError(t, err)
		assert.True(t, released)
	})

	t.Run("DifferentKeys", func(t *testing.T) {
		token1, remaining1, err := client.TryLock(ctx, "key1", 5*time.Second)
		require.NoError(t, err)
		assert.NotEmpty(t, token1)
		assert.Equal(t, time.Duration(0), remaining1)

		token2, remaining2, err := client.TryLock(ctx, "key2", 5*time.Second)
		require.NoError(t, err)
		assert.NotEmpty(t, token2)
		assert.Equal(t, time.Duration(0), remaining2)

		// the same keys are held
		again, remaining, err := client.TryLock(ctx, "key1", 5*time.Second)
		require.NoError(t, err)
		assert.Empty(t, again)
		assert.Greater(t, remaining, time.Duration(0))

		again, remaining, err = client.TryLock(ctx, "key2", 5*time.Second)
		require.NoError(t, err)
		assert.Empty(t, again)
		assert.Greater(t, remaining, time.Duration(0))

		// a token releases only its own key
		released, err := client.ReleaseLock(ctx, "key2", token1)
		require.NoError(t, err)
		assert.False(t, released)

		allowed1, remaining1, err := client.TryAcquireRateLimit(ctx, "rate_key1", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, allowed1)
		assert.Equal(t, time.Duration(0), remaining1)

		allowed2, remaining2, err := client.TryAcquireRateLimit(ctx, "rate_key2", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, allowed2)
		assert.Equal(t, time.Duration(0), remaining2)

		allowed1, remaining1, err = client.TryAcquireRateLimit(ctx, "rate_key1", 5*time.Second)
		require.NoError(t, err)
		assert.False(t, allowed1)
		assert.Greater(t, remaining1, time.Duration(0))

		allowed2, remaining2, err = client.TryAcquireRateLimit(ctx, "rate_key2", 5*time.Second)
		require.NoError(t, err)
		assert.False(t, allowed2)
		assert.Greater(t, remaining2, time.Duration(0))

		released, err = client.ReleaseLock(ctx, "key1", token1)
		require.NoError(t, err)
		assert.True(t, released)
		released, err = client.ReleaseLock(ctx, "key2", token2)
		require.NoError(t, err)
		assert.True(t, released)
	})
}

// cleanup deletes keys created by a subtest.
func cleanup(ctx context.Context, t *testing.T, c *redisclient.RedisClient, keys ...string) {
	t.Helper()
	for _, key := range keys {
		assert.NoError(t, c.Del(ctx, key))
	}
}

// unreachableServer is a Redis URL nothing listens on; clients connect
// lazily, so tests that never send a command need no server.
const unreachableServer = "redis://127.0.0.1:1/0"

func TestClose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	root, err := redisclient.New(&redisclient.Config{Server: unreachableServer})
	require.NoError(t, err)
	child := root.WithPrefix("child")

	assert.NoError(t, child.Close(), "a child does not own the connection")
	require.NoError(t, root.Close())
	// Close is idempotent and keeps the client, so later calls on the root
	// and its children fail instead of panicking (formerly P-062)
	assert.NoError(t, root.Close())
	assert.NotNil(t, root.RawClient())

	var val string
	err = root.Get(ctx, "k", &val)
	assert.ErrorIs(t, err, redis.ErrClosed)
	err = child.Get(ctx, "k", &val)
	assert.ErrorIs(t, err, redis.ErrClosed)

	// a client from NewWithClient leaves the connection to its owner
	raw, err := redisclient.NewRedisClient(&redisclient.Config{Server: unreachableServer})
	require.NoError(t, err)
	wrapped, err := redisclient.NewWithClient(raw)
	require.NoError(t, err)
	require.NoError(t, wrapped.Close())
	require.NoError(t, raw.Close(), "the owner's close is the first")
}

func TestConfigSecrets(t *testing.T) {
	// not parallel: installs a log formatter
	const password = "s3cret-pass"

	var logs bytes.Buffer
	removeFormatter := xlog.InstallFormatter(xlog.NewStringFormatter(&logs))
	t.Cleanup(removeFormatter)

	// only the address is logged (formerly P-045)
	rc, err := redisclient.New(&redisclient.Config{
		Server: "redis://user:" + password + "@127.0.0.1:1/2",
	})
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	// a malformed URL is reported without the URL
	_, err = redisclient.New(&redisclient.Config{
		Server: "redis://user:" + password + "@127.0.0.1:bad/0",
	})
	require.Error(t, err)
	assert.Equal(t, `invalid redis address: invalid port ":bad" after host`, err.Error())

	_, err = redisclient.New(&redisclient.Config{Server: "http://127.0.0.1"})
	require.EqualError(t, err, "invalid redis address: redis: invalid URL scheme: http")

	// removal waits for in-flight log calls, so logs is safe to read after it
	removeFormatter()
	assert.Contains(t, logs.String(), "127.0.0.1:1")
	assert.NotContains(t, logs.String(), password)
}
