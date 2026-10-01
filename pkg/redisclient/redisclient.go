package redisclient

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/url"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/xlog"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "redisclient")

const (
	// lockKeyPrefix names the key of a distributed lock: "lock:<key>".
	lockKeyPrefix = "lock:"
	// rateLimitKeyPrefix names the key of a rate-limit window: "ratelimit:<key>".
	rateLimitKeyPrefix = "ratelimit:"
	// minExpiry is the Redis expiry resolution; shorter lock timeouts and
	// rate-limit windows are rejected.
	minExpiry = time.Millisecond
	// scanBatch is the SCAN COUNT hint of ScanKeys, and defaultScanLimit
	// its limit when none is given.
	scanBatch        = 100
	defaultScanLimit = 1000
)

// DistributedLock provides an owner-bound lock that expires on its own.
type DistributedLock interface {
	// TryLock attempts to acquire the lock for key, expiring after timeout
	// (at least 1ms). It returns the owner token when the lock was
	// acquired; otherwise the token is empty and the remaining time is how
	// long the current holder keeps the lock.
	TryLock(ctx context.Context, key string, timeout time.Duration) (token string, remaining time.Duration, err error)

	// ReleaseLock releases the lock for key only while it is still held
	// with token, the value returned by TryLock. It returns false when the
	// lock expired or is held by another owner.
	ReleaseLock(ctx context.Context, key, token string) (bool, error)

	// IsLocked reports whether anyone holds the lock for key.
	IsLocked(ctx context.Context, key string) (bool, error)
}

// RateLimiter allows one execution per window for a key, across every
// client of the Redis server.
type RateLimiter interface {
	// TryAcquireRateLimit starts a window of the given length (at least
	// 1ms) for key and returns true when no window is active; otherwise it
	// returns false and the time until the active window ends. A denied
	// call does not extend the active window.
	TryAcquireRateLimit(ctx context.Context, key string, window time.Duration) (bool, time.Duration, error)

	// GetRateLimitRemainingTime returns the time until the active window
	// for key ends (at least 1ms while it is active), or 0 when none is
	// active.
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
	// FINDINGS P-095: == and the message match are redundant or too broad.
	return err != nil &&
		(err == ErrNotFound || errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "not found"))
}

// RedisClient implements Provider on top of an embedded *redis.Client.
// The wrapper methods prefix keys (see Key) and wrap errors; the embedded
// client's own methods are also reachable but bypass the prefix.
// Create it with New or NewWithClient, and derive namespaced children with WithPrefix.
type RedisClient struct {
	*redis.Client

	// prefix is "/<name>/" or empty; globPrefix is prefix with its glob
	// metacharacters escaped, for KEYS and SCAN patterns.
	prefix     string
	globPrefix string
	noclose    bool
}

// ensure RedisClient implements Provider interface
var _ Provider = (*RedisClient)(nil)

// NewRedisClient builds a raw *redis.Client from cfg: the URL is parsed,
// TLS is configured from ClientTLS files, Password/User override the URL
// credentials, and maintenance notifications are disabled. Only the server
// address and database are logged, and a malformed URL is reported without
// the URL, which may embed a password.
// The connection is established lazily.
func NewRedisClient(cfg *Config) (*redis.Client, error) {
	options, err := parseURL(cfg.Server)
	if err != nil {
		return nil, err
	}
	logger.KV(xlog.INFO, "redis", options.Addr, "db", options.DB)

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

// parseURL parses a redis://, rediss:// or unix:// URL. A malformed URL is
// reported with the url.Parse reason but not the URL itself, which may
// embed a password.
func parseURL(server string) (*redis.Options, error) {
	options, err := redis.ParseURL(server)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, errors.WithMessage(err, "invalid redis address")
	}
	return options, nil
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
// trimmed and the prefix is cleaned as a path, so "a//b" is "/a/b/"). The
// child's Close is a no-op. Prefixes do not nest: the parent prefix is
// ignored.
func (c *RedisClient) WithPrefix(prefix string) *RedisClient {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		// keys are joined with path.Join, which cleans the prefix too
		prefix = strings.TrimSuffix(path.Clean("/"+prefix), "/") + "/"
	}

	return &RedisClient{
		Client:     c.Client,
		prefix:     prefix,
		globPrefix: escapeGlob(prefix),
		noclose:    true,
	}
}

// Close closes the underlying connection when this client owns it (created
// by New) and returns the close error; for clients from NewWithClient or
// WithPrefix it is a no-op. It is idempotent. Children from WithPrefix
// share the connection: after the root is closed, their commands, like the
// root's, fail with redis.ErrClosed.
func (c *RedisClient) Close() error {
	if c.noclose || c.Client == nil {
		return nil
	}
	err := c.Client.Close()
	if err != nil && !errors.Is(err, redis.ErrClosed) {
		return errors.WithMessage(err, "failed to close redis client")
	}
	return nil
}

// Key returns the full Redis key for key, or key itself when there is no
// prefix. key is cleaned as a rooted path and then joined with the prefix,
// so "a//b", "/a/" and "a" name the same key and ".." cannot leave the
// prefix: "../x" names "<prefix>x".
func (c *RedisClient) Key(key string) string {
	if c.prefix == "" {
		return key
	}
	return path.Join(c.prefix, path.Clean("/"+key))
}

// SubKey strips the client prefix from a full Redis key, inverting Key for
// cleaned keys; the prefix itself, Key(""), maps to "".
func (c *RedisClient) SubKey(key string) string {
	if c.prefix == "" {
		return key
	}
	if key == c.prefix[:len(c.prefix)-1] {
		return ""
	}
	return strings.TrimPrefix(key, c.prefix)
}

// pattern returns the KEYS or SCAN pattern for pattern relative to the
// prefix: pattern is cleaned like a key and the prefix matches literally.
func (c *RedisClient) pattern(pattern string) string {
	if c.prefix == "" {
		return pattern
	}
	return path.Join(c.globPrefix, path.Clean("/"+pattern))
}

// escapeGlob escapes the Redis glob metacharacters in s, so that a pattern
// starting with the result matches s literally. pkg/cache has a copy.
func escapeGlob(s string) string {
	if !strings.ContainsAny(s, globMeta) {
		return s
	}
	var b strings.Builder
	for i := range len(s) {
		if strings.IndexByte(globMeta, s[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// globMeta lists the bytes that are special in a Redis glob pattern.
const globMeta = `*?[]\`

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
			// FINDINGS P-095: the sentinel is not wrapped.
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

// Keys returns the keys, relative to the prefix, that match the Redis glob
// pattern, which is cleaned like a key; the prefix matches literally.
// This method should be used mostly for testing, as in prod many keys maybe returned.
// It blocks and scans the entire Redis keyspace — not safe for large production datasets.
func (c *RedisClient) Keys(ctx context.Context, pattern string) ([]string, error) {
	list, err := c.Client.Keys(ctx, c.pattern(pattern)).Result()
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to list keys %s", pattern)
	}
	for i, key := range list {
		list[i] = c.SubKey(key)
	}
	return list, nil
}

// ScanKeys returns keys matching pattern (relative to the prefix, see Keys) using
// SCAN with a COUNT hint of 100, stopping once at least limit keys were
// collected (limit <= 0 means 1000) or the scan completes. The last batch
// may take the result past limit.
func (c *RedisClient) ScanKeys(ctx context.Context, pattern string, limit int) ([]string, error) {
	var (
		cursor uint64
		keys   []string
		err    error
		batch  []string
	)

	if limit <= 0 {
		limit = defaultScanLimit
	}
	match := c.pattern(pattern)

	for {
		batch, cursor, err = c.Client.Scan(ctx, cursor, match, scanBatch).Result()
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
		// FINDINGS P-104: %s misformats a non-string member.
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

// SAddWithEviction adds member to the set at key and appends it to the
// insertion-order list at listKey when it was not a member yet (removing
// stale list entries for it first); re-adding a member keeps its position.
// While the list holds more than limit entries
// (limit >= 1), its oldest entry is removed from the list and the set. The
// update runs as one Lua script, so it is atomic, and key and listKey must
// differ. A key of the wrong type fails the call before anything is written.
// Adding a new member scans the list (LREM), so its cost grows with limit.
func (c *RedisClient) SAddWithEviction(ctx context.Context, key string, listKey string, limit int64, member string) error {
	keys := []string{c.Key(key), c.Key(listKey)}
	if err := checkEviction(key, keys, limit); err != nil {
		return err
	}
	err := boundedSetScript.Run(ctx, c.Client, keys, limit, member).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to add member to bounded set %s", key)
	}
	return nil
}

// boundedSetScript implements SAddWithEviction: KEYS[1] is the set,
// KEYS[2] the insertion-order list, ARGV[1] the limit and ARGV[2] the
// member. LLEN and SADD fail on a key of the wrong type before any write.
// A new member's stale list entries (left by SRem, an expired set or an
// earlier version) are removed first, so they cannot evict it later.
var boundedSetScript = redis.NewScript(`
local n = redis.call('LLEN', KEYS[2])
if redis.call('SADD', KEYS[1], ARGV[2]) == 1 then
	redis.call('LREM', KEYS[2], 0, ARGV[2])
	n = redis.call('RPUSH', KEYS[2], ARGV[2])
end
local limit = tonumber(ARGV[1])
while n > limit do
	redis.call('SREM', KEYS[1], redis.call('LPOP', KEYS[2]))
	n = n - 1
end
return n
`)

// checkEviction validates the arguments of the bounded set and hash
// helpers: keys holds the full collection and list keys.
func checkEviction(key string, keys []string, limit int64) error {
	if limit < 1 {
		return errors.Errorf("eviction limit for %s must be positive: %d", key, limit)
	}
	if keys[0] == keys[1] {
		return errors.Errorf("eviction list key must differ from %s", key)
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
			// FINDINGS P-095: the sentinel is not wrapped.
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

// HSetWithEviction sets field in the hash at hashKey and appends it to the
// insertion-order list at orderListKey when the field is new (removing
// stale list entries for it first); updating a field keeps its position. While the list holds more than maxFields
// entries (maxFields >= 1), its oldest entry is removed from the list and
// the hash. The update runs as one Lua script, so it is atomic, and hashKey
// and orderListKey must differ. value is encoded as by HSet. A key of the
// wrong type fails the call before anything is written. Adding a new field
// scans the list (LREM), so its cost grows with maxFields.
func (c *RedisClient) HSetWithEviction(ctx context.Context, hashKey, orderListKey string, maxFields int64, field string, value any) error {
	keys := []string{c.Key(hashKey), c.Key(orderListKey)}
	if err := checkEviction(hashKey, keys, maxFields); err != nil {
		return err
	}
	err := boundedHashScript.Run(ctx, c.Client, keys, maxFields, field, value).Err()
	if err != nil {
		return errors.WithMessagef(err, "unable to set field %s in bounded hash %s", field, hashKey)
	}
	return nil
}

// boundedHashScript implements HSetWithEviction: KEYS[1] is the hash,
// KEYS[2] the insertion-order list, ARGV[1] the limit, ARGV[2] the field
// and ARGV[3] the value. LLEN and HSET fail on a key of the wrong type
// before any write. A new field's stale list entries are removed first.
var boundedHashScript = redis.NewScript(`
local n = redis.call('LLEN', KEYS[2])
if redis.call('HSET', KEYS[1], ARGV[2], ARGV[3]) == 1 then
	redis.call('LREM', KEYS[2], 0, ARGV[2])
	n = redis.call('RPUSH', KEYS[2], ARGV[2])
end
local limit = tonumber(ARGV[1])
while n > limit do
	redis.call('HDEL', KEYS[1], redis.call('LPOP', KEYS[2]))
	n = n - 1
end
return n
`)

// Sorted Set (ZSet) operations

// ZAdd adds member with score to the sorted set at key, updating the score
// if the member exists. The go-redis error is returned unwrapped.
func (c *RedisClient) ZAdd(ctx context.Context, key string, score float64, member string) error {
	_, err := c.Client.ZAdd(ctx, c.Key(key), redis.Z{Score: score, Member: member}).Result()
	// FINDINGS P-104: here and in ZIncrBy, ZRem and ZRemRangeByRank.
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

// TryLock attempts to acquire the lock "lock:<key>" with SET NX PX,
// expiring after timeout, which must be at least 1ms. It returns
// (token, 0, nil) when acquired, where token is a random value that
// ReleaseLock requires, otherwise ("", remaining TTL, nil); the remaining
// TTL is 0 for a lock written without expiry. The acquisition and the TTL
// read run in one MULTI/EXEC transaction. Under a prefix, a key whose ".."
// segments would leave the "lock:" namespace is an error, here and in
// ReleaseLock and IsLocked.
func (c *RedisClient) TryLock(ctx context.Context, key string, timeout time.Duration) (string, time.Duration, error) {
	if timeout < minExpiry {
		return "", 0, errors.Errorf("lock timeout for key %s must be at least %s: %s", key, minExpiry, timeout)
	}
	k, err := c.coordKey(lockKeyPrefix, key)
	if err != nil {
		return "", 0, err
	}
	token := rand.Text()
	acquired, remaining, err := c.setNX(ctx, k, token, timeout)
	if err != nil {
		return "", 0, errors.WithMessagef(err, "failed to acquire lock for key: %s", key)
	}
	if !acquired {
		return "", remaining, nil
	}
	return token, 0, nil
}

// ReleaseLock deletes the lock "lock:<key>" only while it holds token, in
// one Lua script (compare-and-delete). It returns true when the lock was
// released and false when it expired or another owner holds it; an empty
// token is an error.
func (c *RedisClient) ReleaseLock(ctx context.Context, key, token string) (bool, error) {
	if token == "" {
		return false, errors.Errorf("empty lock token for key: %s", key)
	}
	k, err := c.coordKey(lockKeyPrefix, key)
	if err != nil {
		return false, err
	}
	n, err := releaseLockScript.Run(ctx, c.Client, []string{k}, token).Int64()
	if err != nil {
		return false, errors.WithMessagef(err, "failed to release lock for key: %s", key)
	}
	return n > 0, nil
}

// releaseLockScript deletes KEYS[1] only while it holds the token ARGV[1].
var releaseLockScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
	return redis.call('DEL', KEYS[1])
end
return 0
`)

// IsLocked reports whether anyone holds the lock "lock:<key>".
func (c *RedisClient) IsLocked(ctx context.Context, key string) (bool, error) {
	k, err := c.coordKey(lockKeyPrefix, key)
	if err != nil {
		return false, err
	}
	n, err := c.Client.Exists(ctx, k).Result()
	if err != nil {
		return false, errors.WithMessagef(err, "failed to check lock for key: %s", key)
	}
	return n > 0, nil
}

// coordKey returns the full key of key in the sub-namespace kind ("lock:"
// or "ratelimit:"). Under a prefix, Key cleans the combined name, so a key
// whose ".." segments would leave the sub-namespace, such as
// "x/../../data", is rejected instead of naming another key; without a
// prefix the name is used as is and cannot leave it.
func (c *RedisClient) coordKey(kind, key string) (string, error) {
	name := kind + key
	if c.prefix != "" && !strings.HasPrefix(path.Clean("/"+name), "/"+kind) {
		return "", errors.Errorf("invalid key %q: leaves the %q namespace", key, strings.TrimSuffix(kind, ":"))
	}
	return c.Key(name), nil
}

// setNX sets the full key k to value with SET NX and expiry ttl and reads
// its remaining TTL in the same MULTI/EXEC transaction. It reports whether
// the key was set and, when it was not, the remaining TTL of the existing
// key (see remainingTTL), or 0 when that key has no expiry.
func (c *RedisClient) setNX(ctx context.Context, k string, value any, ttl time.Duration) (bool, time.Duration, error) {
	var (
		setCmd *redis.BoolCmd
		ttlCmd *redis.DurationCmd
	)
	_, err := c.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		setCmd = pipe.SetNX(ctx, k, value, ttl)
		ttlCmd = pipe.PTTL(ctx, k)
		return nil
	})
	if err != nil {
		return false, 0, err
	}
	if setCmd.Val() {
		return true, 0, nil
	}
	return false, remainingTTL(ttlCmd.Val()), nil
}

// remainingTTL converts a PTTL reply into a remaining time. PTTL counts
// whole milliseconds and reports 0 for a key that expires within the
// current millisecond but still exists, so that is minExpiry: 0 then means
// the key is gone (PTTL -2) or has no expiry (-1).
func remainingTTL(ttl time.Duration) time.Duration {
	switch {
	case ttl < 0:
		return 0
	case ttl == 0:
		return minExpiry
	default:
		return ttl
	}
}

// Rate Limiter implementations

// TryAcquireRateLimit allows one execution per window for key: it starts a
// window by creating "ratelimit:<key>" with SET NX PX and returns
// (true, 0, nil), or returns (false, time until the active window ends,
// nil) when the key exists. A denied call writes nothing, so polling does
// not extend the window, and the check and the write are one atomic
// command. The window, which must be at least 1ms, is measured by the Redis
// server's clock, and the allowed call's window applies until it ends.
// Under a prefix, a key whose ".." segments would leave the "ratelimit:"
// namespace is an error, here and in GetRateLimitRemainingTime.
func (c *RedisClient) TryAcquireRateLimit(ctx context.Context, key string, window time.Duration) (bool, time.Duration, error) {
	if window < minExpiry {
		return false, 0, errors.Errorf("rate limit window for key %s must be at least %s: %s", key, minExpiry, window)
	}
	k, err := c.coordKey(rateLimitKeyPrefix, key)
	if err != nil {
		return false, 0, err
	}
	allowed, remaining, err := c.setNX(ctx, k, window.String(), window)
	if err != nil {
		return false, 0, errors.WithMessagef(err, "failed to acquire rate limit for key: %s", key)
	}
	return allowed, remaining, nil
}

// GetRateLimitRemainingTime returns the time until the active window of
// "ratelimit:<key>" ends, at least 1ms while it is active, or 0 when no
// window is active (or the key has no expiry).
func (c *RedisClient) GetRateLimitRemainingTime(ctx context.Context, key string) (time.Duration, error) {
	k, err := c.coordKey(rateLimitKeyPrefix, key)
	if err != nil {
		return 0, err
	}
	ttl, err := c.Client.PTTL(ctx, k).Result()
	if err != nil {
		return 0, errors.WithMessagef(err, "failed to get rate limit TTL for key: %s", key)
	}
	return remainingTTL(ttl), nil
}
