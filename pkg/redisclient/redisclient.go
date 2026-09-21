package redisclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"reflect"
	"strings"
	"time"

	"cmp"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/xlog"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "redisclient")

// DistributedLock provides distributed locking functionality
type DistributedLock interface {
	// TryLock attempts to acquire a lock with the given key and timeout
	// Returns true if lock was acquired, false otherwise, and remaining time if lock exists
	TryLock(ctx context.Context, key string, timeout time.Duration) (bool, time.Duration, error)

	// ReleaseLock releases the lock for the given key
	// Returns true if lock was released, false if lock didn't exist or was already released
	ReleaseLock(ctx context.Context, key string) (bool, error)

	// IsLocked checks if a lock exists for the given key
	IsLocked(ctx context.Context, key string) (bool, error)
}

// RateLimiter provides rate limiting functionality
type RateLimiter interface {
	// TryAcquireRateLimit attempts to acquire a rate limit slot for the given key
	// Returns true if rate limit allows the operation, false if rate limit exceeded, and remaining time if exceeded
	TryAcquireRateLimit(ctx context.Context, key string, window time.Duration) (bool, time.Duration, error)

	// GetRateLimitRemainingTime returns the remaining time until the rate limit window resets
	GetRateLimitRemainingTime(ctx context.Context, key string) (time.Duration, error)
}

// Provider is the Redis operations interface implemented by *RedisClient;
// depend on it rather than on the concrete type. All keys are relative to
// the client prefix. See the RedisClient methods for per-operation details.
type Provider interface {
	io.Closer

	RateLimiter
	DistributedLock

	// Value operations
	Get(ctx context.Context, key string, value any) error
	Set(ctx context.Context, key string, value any, expiration time.Duration) error
	Del(ctx context.Context, key string) error

	// List operations
	LPush(ctx context.Context, key string, values ...any) error
	RPush(ctx context.Context, key string, values ...any) error
	LPop(ctx context.Context, key string) (string, error)
	RPop(ctx context.Context, key string) (string, error)
	LRange(ctx context.Context, key string, start, stop int64) ([]string, error)
	LTrim(ctx context.Context, key string, start, stop int64) error
	LLen(ctx context.Context, key string) (int64, error)
	LIndex(ctx context.Context, key string, index int64) (string, error)

	// Set operations
	SAdd(ctx context.Context, key string, members ...any) error
	SRem(ctx context.Context, key string, members ...any) error
	SIsMember(ctx context.Context, key string, member any) (bool, error)
	SMembers(ctx context.Context, key string) ([]string, error)
	SCard(ctx context.Context, key string) (int64, error)
	SAddWithEviction(ctx context.Context, key string, listKey string, limit int64, member string) error

	// Sorted Set (ZSet) operations
	ZAdd(ctx context.Context, key string, score float64, member string) error
	ZIncrBy(ctx context.Context, key string, increment float64, member string) error
	ZRem(ctx context.Context, key string, members ...any) error
	ZCard(ctx context.Context, key string) (int64, error)
	// ZRevRangeWithScores returns the specified range of elements in the sorted set stored at key,
	// by index, with scores ordered from high to low.
	// To get top N elements, use ZRevRangeWithScores(key, 0, N-1)
	// To get bottom N elements, use ZRevRangeWithScores(key, -N, -1)
	ZRevRangeWithScores(ctx context.Context, key string, start, stop int64) ([]redis.Z, error)
	// ZRemRangeByRank removes all elements in the sorted set stored at key
	// within the given indexes.
	// Start and stop are 0-based indexes, with 0 being the first element.
	// To remove all ranks below the top N elements, use ZRemRangeByRank(key, 0, -maxN-1)
	ZRemRangeByRank(ctx context.Context, key string, start, stop int64) (int64, error)

	// Hash operations
	HSetMany(ctx context.Context, key string, vals map[string]any) error
	HSet(ctx context.Context, key string, field string, value any) error
	HGet(ctx context.Context, key string, field string) (string, error)
	HGetAll(ctx context.Context, key string) (map[string]string, error)
	HDel(ctx context.Context, key string, fields ...string) error
	HExists(ctx context.Context, key string, field string) (bool, error)
	HKeys(ctx context.Context, key string) ([]string, error)
	HVals(ctx context.Context, key string) ([]string, error)
	HSetWithEviction(ctx context.Context, hashKey, orderListKey string, maxFields int64, field string, value any) error

	// Metadata
	ScanKeys(ctx context.Context, pattern string, limit int) ([]string, error)
	Exists(ctx context.Context, key string) (bool, error)
	Expire(ctx context.Context, key string, expiration time.Duration) (bool, error)
	TTL(ctx context.Context, key string) (time.Duration, error)

	Ping(ctx context.Context) error
}

// Config specifies the Redis connection.
type Config struct {
	// Server is the redis:// or rediss:// URL (see redis.ParseURL).
	Server string `json:"server,omitempty" yaml:"server,omitempty"`
	// TTL is informational for callers; the client itself applies no default expiry.
	TTL time.Duration `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// ClientTLS describes the TLS certs used to connect to the cluster
	ClientTLS *gserver.TLSInfo `json:"client_tls,omitempty" yaml:"client_tls,omitempty"`
	// User is the ACL user name; only applied when Password is set.
	User string `json:"user,omitempty" yaml:"user,omitempty"`
	// Password overrides the credentials embedded in Server.
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
}

// ErrNotFound is returned by Get and HGet for a missing key or field.
var ErrNotFound = errors.New("not found")

// IsNotFoundError reports whether err is (or wraps) ErrNotFound, or whose
// message contains "not found".
func IsNotFoundError(err error) bool {
	return err != nil &&
		(err == ErrNotFound || errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "not found"))
}

// RedisClient implements Provider on top of an embedded *redis.Client.
// The wrapper methods prefix keys (see Key) and wrap errors; the embedded
// client's own methods are also reachable but bypass the prefix.
// Create it with New or NewWithClient, and derive namespaced children with WithPrefix.
type RedisClient struct {
	*redis.Client

	prefix  string
	noclose bool
}

// ensure RedisClient implements Provider interface
var _ Provider = (*RedisClient)(nil)

// NewRedisClient builds a raw *redis.Client from cfg: the URL is parsed,
// TLS is configured from ClientTLS files, Password/User override the URL
// credentials, and maintenance notifications are disabled.
// The connection is established lazily.
func NewRedisClient(cfg *Config) (*redis.Client, error) {
	logger.KV(xlog.INFO, "redis", cfg.Server)

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
			return nil, errors.WithMessage(err, "redis: unable to build TLS configuration")
		}

		options.TLSConfig = tlscfg
	}

	if cfg.Password != "" {
		options.Username = cfg.User
		options.Password = cfg.Password
	}

	// disable maintenance notifications
	options.MaintNotificationsConfig = &maintnotifications.Config{
		Mode: maintnotifications.ModeDisabled,
	}

	return redis.NewClient(options), nil
}

// New creates a root RedisClient (no prefix) from cfg. The returned client
// owns the connection: its Close closes it.
func New(cfg *Config) (*RedisClient, error) {
	rc, err := NewRedisClient(cfg)
	if err != nil {
		return nil, err
	}

	client := &RedisClient{
		Client: rc,
	}

	return client, nil
}

// NewWithClient wraps an existing *redis.Client without a prefix.
// The caller keeps ownership of the connection: Close is a no-op.
// The error is always nil.
func NewWithClient(client *redis.Client) (*RedisClient, error) {
	return &RedisClient{
		Client:  client,
		noclose: true,
	}, nil
}

// RawClient returns the raw Redis client
// This is useful for using the client in a context where the Provider interface is not used
func (c *RedisClient) RawClient() *redis.Client {
	return c.Client
}

// WithPrefix returns a child client sharing the connection whose keys are
// namespaced under "/<prefix>/" (surrounding spaces and slashes are
// trimmed). The child's Close is a no-op. Prefixes do not nest: the parent
// prefix is ignored.
func (c *RedisClient) WithPrefix(prefix string) *RedisClient {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix = "/" + prefix + "/"
	}

	// TODO: parent prefix?
	return &RedisClient{
		Client:  c.Client,
		prefix:  prefix,
		noclose: true,
	}
}

// Close closes the underlying connection when this client owns it (created
// by New); for clients from NewWithClient or WithPrefix it is a no-op.
// Close errors are logged, never returned; the client must not be used afterwards.
func (c *RedisClient) Close() error {
	if c.Client != nil && !c.noclose {
		// close the client only if no prefix is set
		// otherwise, it is a shared client
		if err := c.Client.Close(); err != nil {
			logger.KV(xlog.ERROR, "reason", "redis_close", "err", err.Error())
		}
		c.Client = nil
	}
	return nil
}

// Key returns the full Redis key for key: the prefix joined with key using
// path.Join (so "a//b" and "../x" are cleaned), or key itself when there is no prefix.
func (c *RedisClient) Key(key string) string {
	if c.prefix == "" {
		return key
	}
	return path.Join(c.prefix, key)
}

// SubKey strips the client prefix from a full Redis key, inverting Key.
func (c *RedisClient) SubKey(key string) string {
	if c.prefix == "" {
		return key
	}
	return strings.TrimPrefix(key, c.prefix)
}

// Get loads the value stored under key into v, which must be a non-nil
// pointer (see UnmarshalStringCmd). It returns ErrNotFound for a missing key.
func (c *RedisClient) Get(ctx context.Context, key string, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return &json.InvalidUnmarshalError{Type: reflect.TypeOf(v)}
	}

	val := c.Client.Get(ctx, c.Key(key))
	err := val.Err()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrNotFound
		}
		return errors.Wrapf(err, "failed to get key: %s", key)
	}

	return UnmarshalStringCmd(val, v)
}

// Set stores v under key (see Marshal for the encoding) with the given
// expiration; 0 means no expiry and redis.KeepTTL keeps the existing one.
func (c *RedisClient) Set(ctx context.Context, key string, v any, expiration time.Duration) error {
	value, err := Marshal(v)
	if err != nil {
		return err
	}

	err = c.Client.Set(ctx, c.Key(key), value, expiration).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to set value for key %s", key)
	}
	return nil
}

// Del removes key; a missing key is not an error.
func (c *RedisClient) Del(ctx context.Context, key string) error {
	err := c.Client.Del(ctx, c.Key(key)).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to delete key %s", key)
	}
	return nil
}

// LPush prepends values to the list at key.
func (c *RedisClient) LPush(ctx context.Context, key string, values ...any) error {
	err := c.Client.LPush(ctx, c.Key(key), values...).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to push values to list %s", key)
	}
	return nil
}

// RPush appends values to the list at key.
func (c *RedisClient) RPush(ctx context.Context, key string, values ...any) error {
	err := c.Client.RPush(ctx, c.Key(key), values...).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to push values to list %s", key)
	}
	return nil
}

// LPop removes and returns the first element of the list at key.
// An empty or missing list yields a wrapped redis.Nil error, not ErrNotFound.
func (c *RedisClient) LPop(ctx context.Context, key string) (string, error) {
	val, err := c.Client.LPop(ctx, c.Key(key)).Result()
	if err != nil {
		return "", errors.WithMessagef(err, "unable to pop value from list %s", key)
	}
	return val, nil
}

// RPop removes and returns the last element of the list at key.
// An empty or missing list yields a wrapped redis.Nil error, not ErrNotFound.
func (c *RedisClient) RPop(ctx context.Context, key string) (string, error) {
	val, err := c.Client.RPop(ctx, c.Key(key)).Result()
	if err != nil {
		return "", errors.WithMessagef(err, "unable to pop value from list %s", key)
	}
	return val, nil
}

// LRange returns the elements of the list at key between the start and
// stop indexes (inclusive, negative counts from the end).
func (c *RedisClient) LRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	val, err := c.Client.LRange(ctx, c.Key(key), start, stop).Result()
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to range values from list %s", key)
	}
	return val, nil
}

// LTrim keeps only the elements of the list at key between start and stop.
func (c *RedisClient) LTrim(ctx context.Context, key string, start, stop int64) error {
	err := c.Client.LTrim(ctx, c.Key(key), start, stop).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to trim list %s", key)
	}
	return nil
}

// LLen returns the length of the list at key (0 when missing).
func (c *RedisClient) LLen(ctx context.Context, key string) (int64, error) {
	val, err := c.Client.LLen(ctx, c.Key(key)).Result()
	if err != nil {
		return 0, errors.WithMessagef(err, "unable to get length of list %s", key)
	}
	return val, nil
}

// LIndex returns the element at index in the list at key.
func (c *RedisClient) LIndex(ctx context.Context, key string, index int64) (string, error) {
	val, err := c.Client.LIndex(ctx, c.Key(key), index).Result()
	if err != nil {
		return "", errors.WithMessagef(err, "unable to get index %d from list %s", index, key)
	}
	return val, nil
}

// Exists reports whether key exists.
func (c *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	val, err := c.Client.Exists(ctx, c.Key(key)).Result()
	if err != nil {
		return false, errors.WithMessagef(err, "unable to check if key %s exists", key)
	}
	return val > 0, nil
}

// Expire sets the TTL of key and reports whether the key existed.
func (c *RedisClient) Expire(ctx context.Context, key string, expiration time.Duration) (bool, error) {
	val, err := c.Client.Expire(ctx, c.Key(key), expiration).Result()
	if err != nil {
		return false, errors.WithMessagef(err, "unable to set expiration for key %s", key)
	}
	return val, nil
}

// TTL returns the remaining TTL of key (-1 for no expiry, -2 when missing).
func (c *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	val, err := c.Client.TTL(ctx, c.Key(key)).Result()
	if err != nil {
		return 0, errors.WithMessagef(err, "unable to get TTL for key %s", key)
	}
	return val, nil
}

// Ping checks connectivity to the server.
func (c *RedisClient) Ping(ctx context.Context) error {
	_, err := c.Client.Ping(ctx).Result()
	if err != nil {
		return errors.WithMessagef(err, "unable to ping redis")
	}
	return nil
}

// Keys returns list of keys.
// This method should be used mostly for testing, as in prod many keys maybe returned.
// It blocks and scans the entire Redis keyspace — not safe for large production datasets.
func (c *RedisClient) Keys(ctx context.Context, pattern string) ([]string, error) {
	res := c.Client.Keys(ctx, c.Key(pattern))
	if res.Err() != nil {
		return nil, res.Err()
	}
	list := res.Val()
	for i, key := range list {
		list[i] = c.SubKey(key)
	}
	return list, nil
}

// ScanKeys returns keys matching pattern (relative to the prefix) using
// SCAN in batches of 100, stopping once at least limit keys were collected
// (limit <= 0 means 1000) or the scan completes. It may return up to 99 keys
// more than limit.
func (c *RedisClient) ScanKeys(ctx context.Context, pattern string, limit int) ([]string, error) {
	var (
		cursor uint64
		keys   []string
		err    error
		batch  []string
	)

	limit = cmp.Or(limit, 1000)

	for {
		batch, cursor, err = c.Client.Scan(ctx, cursor, c.Key(pattern), 100).Result()
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to scan keys")
		}
		keys = append(keys, batch...)
		if cursor == 0 || len(keys) >= limit {
			break
		}
	}

	for i, key := range keys {
		keys[i] = c.SubKey(key)
	}

	return keys, nil
}

// SAdd adds members to the set at key.
func (c *RedisClient) SAdd(ctx context.Context, key string, members ...any) error {
	err := c.Client.SAdd(ctx, c.Key(key), members...).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to add members to set %s", key)
	}
	return nil
}

// SRem removes members from the set at key.
func (c *RedisClient) SRem(ctx context.Context, key string, members ...any) error {
	err := c.Client.SRem(ctx, c.Key(key), members...).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to remove members from set %s", key)
	}
	return nil
}

// SIsMember reports whether member belongs to the set at key.
func (c *RedisClient) SIsMember(ctx context.Context, key string, member any) (bool, error) {
	val, err := c.Client.SIsMember(ctx, c.Key(key), member).Result()
	if err != nil {
		return false, errors.WithMessagef(err, "unable to check if member %s exists in set %s", member, key)
	}
	return val, nil
}

// SMembers returns all members of the set at key.
func (c *RedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	val, err := c.Client.SMembers(ctx, c.Key(key)).Result()
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to get members from set %s", key)
	}
	return val, nil
}

// SCard returns the number of members of the set at key.
func (c *RedisClient) SCard(ctx context.Context, key string) (int64, error) {
	val, err := c.Client.SCard(ctx, c.Key(key)).Result()
	if err != nil {
		return 0, errors.WithMessagef(err, "unable to get card from set %s", key)
	}
	return val, nil
}

// SAddWithEviction adds member to the set at key and records the insertion
// order in the list at listKey; when the list grows beyond limit the oldest
// member is removed from both. The steps are separate commands (not
// atomic) and errors from the eviction step are ignored.
func (c *RedisClient) SAddWithEviction(ctx context.Context, key string, listKey string, limit int64, member string) error {
	// Add to Set
	err := c.SAdd(ctx, key, member)
	if err != nil {
		return err
	}

	// Track in List
	if err := c.RPush(ctx, listKey, member); err != nil {
		return err
	}

	// Enforce cap
	length, _ := c.LLen(ctx, listKey)
	if length > limit {
		oldest, _ := c.LPop(ctx, listKey)
		_ = c.SRem(ctx, key, oldest)
	}

	return nil
}

// HSetMany sets several fields of the hash at key in one HSET command.
// An empty map is a no-op.
func (c *RedisClient) HSetMany(ctx context.Context, key string, values map[string]any) error {
	if len(values) == 0 {
		return nil
	}

	m := make([]any, 0, len(values)*2)
	for k, v := range values {
		m = append(m, k, v)
	}

	err := c.Client.HSet(ctx, c.Key(key), m).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to set hash %s", key)
	}
	return nil
}

// HSet sets a single field of the hash at key.
func (c *RedisClient) HSet(ctx context.Context, key string, field string, value any) error {
	err := c.Client.HSet(ctx, c.Key(key), field, value).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to set field %s in hash %s", field, key)
	}
	return nil
}

// HGet returns a field of the hash at key, or ErrNotFound when the field
// or the hash is missing.
func (c *RedisClient) HGet(ctx context.Context, key string, field string) (string, error) {
	val, err := c.Client.HGet(ctx, c.Key(key), field).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrNotFound
		}
		return "", errors.WithMessagef(err, "unable to get field %s from hash %s", field, key)
	}
	return val, nil
}

// HGetAll returns all fields of the hash at key (empty map when missing).
func (c *RedisClient) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	val, err := c.Client.HGetAll(ctx, c.Key(key)).Result()
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to get all fields from hash %s", key)
	}
	return val, nil
}

// HDel removes fields from the hash at key.
func (c *RedisClient) HDel(ctx context.Context, key string, fields ...string) error {
	err := c.Client.HDel(ctx, c.Key(key), fields...).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to delete fields from hash %s", key)
	}
	return nil
}

// HExists reports whether the hash at key has field.
func (c *RedisClient) HExists(ctx context.Context, key string, field string) (bool, error) {
	val, err := c.Client.HExists(ctx, c.Key(key), field).Result()
	if err != nil {
		return false, errors.WithMessagef(err, "unable to check if field %s exists in hash %s", field, key)
	}
	return val, nil
}

// HKeys returns the field names of the hash at key.
func (c *RedisClient) HKeys(ctx context.Context, key string) ([]string, error) {
	val, err := c.Client.HKeys(ctx, c.Key(key)).Result()
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to get keys from hash %s", key)
	}
	return val, nil
}

// HVals returns the field values of the hash at key.
func (c *RedisClient) HVals(ctx context.Context, key string) ([]string, error) {
	val, err := c.Client.HVals(ctx, c.Key(key)).Result()
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to get values from hash %s", key)
	}
	return val, nil
}

// HSetWithEviction sets field in the hash at hashKey and records the
// insertion order in the list at orderListKey; when the list grows beyond
// maxFields the oldest field is deleted from the hash. The steps are
// separate commands (not atomic) and errors from the eviction step are ignored.
func (c *RedisClient) HSetWithEviction(ctx context.Context, hashKey, orderListKey string, maxFields int64, field string, value any) error {
	// Set the hash field
	err := c.Client.HSet(ctx, c.Key(hashKey), field, value).Err()
	if err != nil {
		return err
	}

	// Track field order in a list
	if err := c.Client.RPush(ctx, c.Key(orderListKey), field).Err(); err != nil {
		return err
	}

	// Trim if over limit
	length, _ := c.Client.LLen(ctx, c.Key(orderListKey)).Result()
	if length > maxFields {
		oldestField, _ := c.Client.LPop(ctx, c.Key(orderListKey)).Result()
		c.Client.HDel(ctx, c.Key(hashKey), oldestField)
	}

	return nil
}

// Sorted Set (ZSet) operations

// ZAdd adds member with score to the sorted set at key, updating the score
// if the member exists. The go-redis error is returned unwrapped.
func (c *RedisClient) ZAdd(ctx context.Context, key string, score float64, member string) error {
	_, err := c.Client.ZAdd(ctx, c.Key(key), redis.Z{Score: score, Member: member}).Result()
	return err
}

// ZIncrBy adds increment to the score of member in the sorted set at key.
// The go-redis error is returned unwrapped.
func (c *RedisClient) ZIncrBy(ctx context.Context, key string, increment float64, member string) error {
	_, err := c.Client.ZIncrBy(ctx, c.Key(key), increment, member).Result()
	return err
}

// ZRem removes members from the sorted set at key.
// The go-redis error is returned unwrapped.
func (c *RedisClient) ZRem(ctx context.Context, key string, members ...any) error {
	_, err := c.Client.ZRem(ctx, c.Key(key), members...).Result()
	return err
}

// ZRevRangeWithScores returns the elements of the sorted set at key between
// the start and stop ranks ordered by score from high to low, with scores.
// Use (0, N-1) for the top N and (-N, -1) for the bottom N.
func (c *RedisClient) ZRevRangeWithScores(ctx context.Context, key string, start, stop int64) ([]redis.Z, error) {
	// ZRevRangeWithScores returns the specified range of elements in the sorted set stored at key,
	// by index, with scores ordered from high to low.
	// The elements are considered to be ordered from high to low by their score.
	// The elements with equal scores are returned in lexicographical order.
	val, err := c.Client.ZRevRangeWithScores(ctx, c.Key(key), start, stop).Result()
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to get range from sorted set %s", key)
	}
	return val, nil
}

// ZCard returns the number of members of the sorted set at key.
func (c *RedisClient) ZCard(ctx context.Context, key string) (int64, error) {
	val, err := c.Client.ZCard(ctx, c.Key(key)).Result()
	if err != nil {
		return 0, errors.WithMessagef(err, "unable to get cardinality of sorted set %s", key)
	}
	return val, nil
}

// ZRemRangeByRank removes the elements of the sorted set at key between the
// start and stop ranks (0-based, ascending by score) and returns the count
// removed. Use (0, -N-1) to keep only the top N. The go-redis error is
// returned unwrapped.
func (c *RedisClient) ZRemRangeByRank(ctx context.Context, key string, start, stop int64) (int64, error) {
	val, err := c.Client.ZRemRangeByRank(ctx, c.Key(key), start, stop).Result()
	return val, err
}

// Distributed Lock implementations

// TryLock attempts to acquire the lock "lock:<key>" with SET NX EX, expiring
// after timeout. It returns (true, 0, nil) when acquired, otherwise
// (false, remaining TTL, nil). The lock is not owner-bound: any caller can
// release it with ReleaseLock.
func (c *RedisClient) TryLock(ctx context.Context, key string, timeout time.Duration) (bool, time.Duration, error) {
	lockKey := "lock:" + key
	lockValue := time.Now().UnixNano() // Use timestamp as lock value for uniqueness

	// Use SET with NX (only if not exists) and EX (expiration) to atomically acquire lock
	result, err := c.Client.SetNX(ctx, c.Key(lockKey), lockValue, timeout).Result()
	if err != nil {
		return false, 0, errors.WithMessagef(err, "failed to acquire lock for key: %s", key)
	}

	if result {
		// Lock was acquired successfully
		return true, 0, nil
	}

	// Lock was not acquired, get remaining time
	ttl, err := c.Client.TTL(ctx, c.Key(lockKey)).Result()
	if err != nil {
		return false, 0, errors.WithMessagef(err, "failed to get lock TTL for key: %s", key)
	}

	return false, ttl, nil
}

// ReleaseLock releases a distributed lock by deleting the lock key
// Note: This is a simple implementation. For production use, you might want to verify
// that the lock belongs to the current process before releasing it
func (c *RedisClient) ReleaseLock(ctx context.Context, key string) (bool, error) {
	lockKey := "lock:" + key

	// Check if lock exists before attempting to delete
	exists, err := c.Exists(ctx, lockKey)
	if err != nil {
		return false, errors.WithMessagef(err, "failed to check lock existence for key: %s", key)
	}

	if !exists {
		return false, nil // Lock doesn't exist
	}

	// Delete the lock
	deleted, err := c.Client.Del(ctx, c.Key(lockKey)).Result()
	if err != nil {
		return false, errors.WithMessagef(err, "failed to release lock for key: %s", key)
	}

	return deleted > 0, nil
}

// IsLocked checks if a lock exists for the given key
func (c *RedisClient) IsLocked(ctx context.Context, key string) (bool, error) {
	lockKey := "lock:" + key
	return c.Exists(ctx, lockKey)
}

// Rate Limiter implementations

// TryAcquireRateLimit implements a sliding-window limiter that allows one
// execution per window for key, using the sorted set "ratelimit:<key>" and
// the "ratelimit_window:<key>" value. Every call, allowed or not, records
// its timestamp, so continuous denied attempts keep the window busy.
// It returns (true, 0, nil) when allowed, otherwise (false, time until the
// window resets, nil). The commands are pipelined but not transactional.
func (c *RedisClient) TryAcquireRateLimit(ctx context.Context, key string, window time.Duration) (bool, time.Duration, error) {
	rateLimitKey := "ratelimit:" + key
	windowKey := "ratelimit_window:" + key
	now := time.Now()
	windowStart := now.Add(-window)

	// Use Redis pipeline for atomic operations
	pipe := c.Pipeline()

	// Remove expired entries (older than window)
	pipe.ZRemRangeByScore(ctx, c.Key(rateLimitKey), "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	// Count current entries before adding new one
	countCmd := pipe.ZCard(ctx, c.Key(rateLimitKey))

	// Add current timestamp
	pipe.ZAdd(ctx, c.Key(rateLimitKey), redis.Z{
		Score:  float64(now.UnixNano()),
		Member: now.UnixNano(),
	})

	// Store the window duration for GetRemainingTime
	pipe.Set(ctx, c.Key(windowKey), window.Nanoseconds(), window)

	// Set expiration on the key to prevent memory leaks
	pipe.Expire(ctx, c.Key(rateLimitKey), window)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, errors.WithMessagef(err, "failed to execute rate limit operations for key: %s", key)
	}

	// Check if we had any entries before adding the current one
	count := countCmd.Val()

	if count == 0 {
		// Allow if no previous executions in the window
		return true, 0, nil
	}

	// Rate limit exceeded, get remaining time
	remaining, err := c.GetRateLimitRemainingTime(ctx, key)
	if err != nil {
		return false, 0, errors.WithMessagef(err, "failed to get remaining time for key: %s", key)
	}

	return false, remaining, nil
}

// GetRateLimitRemainingTime returns the remaining time until the rate limit window resets
func (c *RedisClient) GetRateLimitRemainingTime(ctx context.Context, key string) (time.Duration, error) {
	rateLimitKey := "ratelimit:" + key
	windowKey := "ratelimit_window:" + key

	// Get the oldest entry in the sorted set
	entries, err := c.Client.ZRangeWithScores(ctx, c.Key(rateLimitKey), 0, 0).Result()
	if err != nil {
		return 0, errors.WithMessagef(err, "failed to get rate limit entries for key: %s", key)
	}

	if len(entries) == 0 {
		return 0, nil // No rate limit active
	}

	// Get the stored window duration
	var windowDurationNs int64
	err = c.Get(ctx, windowKey, &windowDurationNs)
	if err != nil {
		// If we can't get the window duration, assume 5 seconds (for backward compatibility)
		windowDurationNs = 5 * time.Second.Nanoseconds()
	}
	windowDuration := time.Duration(windowDurationNs)

	// Get the timestamp of the oldest entry
	oldestTimestamp := int64(entries[0].Score)
	oldestTime := time.Unix(0, oldestTimestamp)

	// Calculate when the window will reset (oldest entry + window duration)
	windowReset := oldestTime.Add(windowDuration)

	remaining := time.Until(windowReset)
	if remaining < 0 {
		return 0, nil
	}

	return remaining, nil
}
