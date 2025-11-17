package redisclient_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/effective-security/porto/pkg/redisclient"
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

	t.Run("DistributedLock", func(t *testing.T) {
		// Test TryLock - should acquire lock successfully
		acquired, remaining, err := client.TryLock(ctx, "test_lock", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, acquired)
		assert.Equal(t, time.Duration(0), remaining)

		// Test IsLocked - should return true
		locked, err := client.IsLocked(ctx, "test_lock")
		require.NoError(t, err)
		assert.True(t, locked)

		// Test TryLock again - should fail (lock already exists)
		acquired2, remaining2, err := client.TryLock(ctx, "test_lock", 5*time.Second)
		require.NoError(t, err)
		assert.False(t, acquired2)
		assert.True(t, remaining2 > 0)

		// Test ReleaseLock - should release successfully
		released, err := client.ReleaseLock(ctx, "test_lock")
		require.NoError(t, err)
		assert.True(t, released)

		// Test IsLocked after release - should return false
		locked, err = client.IsLocked(ctx, "test_lock")
		require.NoError(t, err)
		assert.False(t, locked)

		// Test ReleaseLock on non-existent lock - should return false
		released, err = client.ReleaseLock(ctx, "test_lock")
		require.NoError(t, err)
		assert.False(t, released)

		// Test lock expiration
		acquired, remaining, err = client.TryLock(ctx, "expire_lock", 1*time.Second)
		require.NoError(t, err)
		assert.True(t, acquired)
		assert.Equal(t, time.Duration(0), remaining)

		// Wait for lock to expire
		time.Sleep(2 * time.Second)

		// Lock should have expired
		locked, err = client.IsLocked(ctx, "expire_lock")
		require.NoError(t, err)
		assert.False(t, locked)

		// Should be able to acquire lock again after expiration
		acquired, remaining, err = client.TryLock(ctx, "expire_lock", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, acquired)
		assert.Equal(t, time.Duration(0), remaining)

		// Cleanup
		client.ReleaseLock(ctx, "expire_lock")
	})

	t.Run("RateLimiter", func(t *testing.T) {
		// Test TryAcquireRateLimit - should acquire rate limit slot successfully
		allowed, remaining, err := client.TryAcquireRateLimit(ctx, "test_rate_limit", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, time.Duration(0), remaining)

		// Test TryAcquireRateLimit again immediately - should fail (rate limit exceeded)
		allowed2, remaining2, err := client.TryAcquireRateLimit(ctx, "test_rate_limit", 5*time.Second)
		require.NoError(t, err)
		assert.False(t, allowed2)
		assert.True(t, remaining2 > 0)
		assert.True(t, remaining2 <= 5*time.Second)

		// Test GetRateLimitRemainingTime - should return remaining time
		remaining3, err := client.GetRateLimitRemainingTime(ctx, "test_rate_limit")
		require.NoError(t, err)
		assert.True(t, remaining3 > 0)
		assert.True(t, remaining3 <= 5*time.Second)

		// Wait for rate limit to expire
		time.Sleep(6 * time.Second)

		// Should be able to acquire rate limit slot again after expiration
		allowed3, remaining4, err := client.TryAcquireRateLimit(ctx, "test_rate_limit", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, allowed3)
		assert.Equal(t, time.Duration(0), remaining4)

		// Test GetRateLimitRemainingTime on non-existent rate limit - should return 0
		remaining, err = client.GetRateLimitRemainingTime(ctx, "non_existent_rate_limit")
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), remaining)
	})

	t.Run("ConcurrentLocking", func(t *testing.T) {
		// Test concurrent lock acquisition
		const numGoroutines = 10
		results := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				acquired, _, err := client.TryLock(ctx, "concurrent_lock", 5*time.Second)
				require.NoError(t, err)
				results <- acquired
			}()
		}

		// Collect results
		acquiredCount := 0
		for i := 0; i < numGoroutines; i++ {
			if <-results {
				acquiredCount++
			}
		}

		// Only one should have acquired the lock
		assert.Equal(t, 1, acquiredCount)

		// Cleanup
		client.ReleaseLock(ctx, "concurrent_lock")
	})

	t.Run("ConcurrentRateLimiting", func(t *testing.T) {
		// Test concurrent rate limit acquisition
		const numGoroutines = 10
		results := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				allowed, _, err := client.TryAcquireRateLimit(ctx, "concurrent_rate_limit", 5*time.Second)
				require.NoError(t, err)
				results <- allowed
			}()
		}

		// Collect results
		allowedCount := 0
		for i := 0; i < numGoroutines; i++ {
			if <-results {
				allowedCount++
			}
		}

		// Only one should be allowed
		assert.Equal(t, 1, allowedCount)
	})

	t.Run("KeyPrefixing", func(t *testing.T) {
		// Test that keys are properly prefixed
		acquired, remaining, err := client.TryLock(ctx, "prefix_test", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, acquired)
		assert.Equal(t, time.Duration(0), remaining)

		// Check that the key exists with prefix
		exists, err := client.Exists(ctx, "lock:prefix_test")
		require.NoError(t, err)
		assert.True(t, exists)

		// Test rate limiting with prefix
		allowed, remaining, err := client.TryAcquireRateLimit(ctx, "prefix_rate_test", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, time.Duration(0), remaining)

		// Check that the rate limit key exists with prefix
		exists, err = client.Exists(ctx, "ratelimit:prefix_rate_test")
		require.NoError(t, err)
		assert.True(t, exists)

		// Cleanup
		client.ReleaseLock(ctx, "prefix_test")
	})

	t.Run("DifferentKeys", func(t *testing.T) {
		// Test that different keys don't interfere with each other

		// Acquire locks on different keys
		acquired1, remaining1, err := client.TryLock(ctx, "key1", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, acquired1)
		assert.Equal(t, time.Duration(0), remaining1)

		acquired2, remaining2, err := client.TryLock(ctx, "key2", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, acquired2)
		assert.Equal(t, time.Duration(0), remaining2)

		// Try to acquire the same keys again - should fail
		acquired1Again, remaining1Again, err := client.TryLock(ctx, "key1", 5*time.Second)
		require.NoError(t, err)
		assert.False(t, acquired1Again)
		assert.True(t, remaining1Again > 0)

		acquired2Again, remaining2Again, err := client.TryLock(ctx, "key2", 5*time.Second)
		require.NoError(t, err)
		assert.False(t, acquired2Again)
		assert.True(t, remaining2Again > 0)

		// Test rate limiting on different keys
		allowed1, remaining1, err := client.TryAcquireRateLimit(ctx, "rate_key1", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, allowed1)
		assert.Equal(t, time.Duration(0), remaining1)

		allowed2, remaining2, err := client.TryAcquireRateLimit(ctx, "rate_key2", 5*time.Second)
		require.NoError(t, err)
		assert.True(t, allowed2)
		assert.Equal(t, time.Duration(0), remaining2)

		// Try to acquire the same rate limits again - should fail
		allowed1Again, remaining1Again, err := client.TryAcquireRateLimit(ctx, "rate_key1", 5*time.Second)
		require.NoError(t, err)
		assert.False(t, allowed1Again)
		assert.True(t, remaining1Again > 0)

		allowed2Again, remaining2Again, err := client.TryAcquireRateLimit(ctx, "rate_key2", 5*time.Second)
		require.NoError(t, err)
		assert.False(t, allowed2Again)
		assert.True(t, remaining2Again > 0)

		// Cleanup
		client.ReleaseLock(ctx, "key1")
		client.ReleaseLock(ctx, "key2")
	})
}
