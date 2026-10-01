package redisclient_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/redisclient"
	"github.com/effective-security/xpki/testca"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClosedClientErrors checks that every Provider method of a closed
// client returns redis.ErrClosed, wrapped with the relative key where the
// method documents it, and its zero result. A child shares the closed
// connection, so no command reaches a server.
func TestClosedClientErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	root, err := redisclient.New(&redisclient.Config{Server: unreachableServer})
	require.NoError(t, err)
	require.NoError(t, root.Close())
	c := root.WithPrefix("closed")

	closed := redis.ErrClosed.Error()
	tcases := []struct {
		name string
		call func() (any, error)
		want any
		// err is the expected message without the trailing redis error
		err string
	}{
		{name: "Get", call: func() (any, error) {
			var s string
			return nil, c.Get(ctx, "k", &s)
		}, err: "failed to get key: k: "},
		{name: "Set", call: func() (any, error) {
			return nil, c.Set(ctx, "k", "v", time.Minute)
		}, err: "unable to set value for key k: "},
		{name: "Del", call: func() (any, error) {
			return nil, c.Del(ctx, "k")
		}, err: "unable to delete key k: "},
		{name: "LPush", call: func() (any, error) {
			return nil, c.LPush(ctx, "l", "v")
		}, err: "unable to push values to list l: "},
		{name: "RPush", call: func() (any, error) {
			return nil, c.RPush(ctx, "l", "v")
		}, err: "unable to push values to list l: "},
		{name: "LPop", call: func() (any, error) {
			return c.LPop(ctx, "l")
		}, want: "", err: "unable to pop value from list l: "},
		{name: "RPop", call: func() (any, error) {
			return c.RPop(ctx, "l")
		}, want: "", err: "unable to pop value from list l: "},
		{name: "LRange", call: func() (any, error) {
			return c.LRange(ctx, "l", 0, -1)
		}, want: []string(nil), err: "unable to range values from list l: "},
		{name: "LTrim", call: func() (any, error) {
			return nil, c.LTrim(ctx, "l", 0, 1)
		}, err: "unable to trim list l: "},
		{name: "LLen", call: func() (any, error) {
			return c.LLen(ctx, "l")
		}, want: int64(0), err: "unable to get length of list l: "},
		{name: "LIndex", call: func() (any, error) {
			return c.LIndex(ctx, "l", 2)
		}, want: "", err: "unable to get index 2 from list l: "},
		{name: "SAdd", call: func() (any, error) {
			return nil, c.SAdd(ctx, "s", "m")
		}, err: "unable to add members to set s: "},
		{name: "SRem", call: func() (any, error) {
			return nil, c.SRem(ctx, "s", "m")
		}, err: "unable to remove members from set s: "},
		// FINDINGS P-104: the member is formatted with %s although it is any
		{name: "SIsMember", call: func() (any, error) {
			return c.SIsMember(ctx, "s", "m")
		}, want: false, err: "unable to check if member m exists in set s: "},
		{name: "SMembers", call: func() (any, error) {
			return c.SMembers(ctx, "s")
		}, want: []string(nil), err: "unable to get members from set s: "},
		{name: "SCard", call: func() (any, error) {
			return c.SCard(ctx, "s")
		}, want: int64(0), err: "unable to get card from set s: "},
		{name: "SAddWithEviction", call: func() (any, error) {
			return nil, c.SAddWithEviction(ctx, "s", "sl", 3, "m")
		}, err: "unable to add member to bounded set s: "},
		// the sorted set helpers return the go-redis error unwrapped.
		// FINDINGS P-104: unwrapped errors are recorded as a defect; once
		// they are wrapped, add the expected messages to these four rows.
		{name: "ZAdd", call: func() (any, error) {
			return nil, c.ZAdd(ctx, "z", 1, "m")
		}},
		{name: "ZIncrBy", call: func() (any, error) {
			return nil, c.ZIncrBy(ctx, "z", 1, "m")
		}},
		{name: "ZRem", call: func() (any, error) {
			return nil, c.ZRem(ctx, "z", "m")
		}},
		{name: "ZRemRangeByRank", call: func() (any, error) {
			return c.ZRemRangeByRank(ctx, "z", 0, -1)
		}, want: int64(0)},
		{name: "ZCard", call: func() (any, error) {
			return c.ZCard(ctx, "z")
		}, want: int64(0), err: "unable to get cardinality of sorted set z: "},
		{name: "ZRevRangeWithScores", call: func() (any, error) {
			return c.ZRevRangeWithScores(ctx, "z", 0, -1)
		}, want: []redis.Z(nil), err: "unable to get range from sorted set z: "},
		{name: "HSetMany", call: func() (any, error) {
			return nil, c.HSetMany(ctx, "h", map[string]any{"f": "v"})
		}, err: "unable to set hash h: "},
		{name: "HSet", call: func() (any, error) {
			return nil, c.HSet(ctx, "h", "f", "v")
		}, err: "unable to set field f in hash h: "},
		{name: "HGet", call: func() (any, error) {
			return c.HGet(ctx, "h", "f")
		}, want: "", err: "unable to get field f from hash h: "},
		{name: "HGetAll", call: func() (any, error) {
			return c.HGetAll(ctx, "h")
		}, want: map[string]string(nil), err: "unable to get all fields from hash h: "},
		{name: "HDel", call: func() (any, error) {
			return nil, c.HDel(ctx, "h", "f")
		}, err: "unable to delete fields from hash h: "},
		{name: "HExists", call: func() (any, error) {
			return c.HExists(ctx, "h", "f")
		}, want: false, err: "unable to check if field f exists in hash h: "},
		{name: "HKeys", call: func() (any, error) {
			return c.HKeys(ctx, "h")
		}, want: []string(nil), err: "unable to get keys from hash h: "},
		{name: "HVals", call: func() (any, error) {
			return c.HVals(ctx, "h")
		}, want: []string(nil), err: "unable to get values from hash h: "},
		{name: "HSetWithEviction", call: func() (any, error) {
			return nil, c.HSetWithEviction(ctx, "h", "hl", 3, "f", "v")
		}, err: "unable to set field f in bounded hash h: "},
		{name: "Keys", call: func() (any, error) {
			return c.Keys(ctx, "k*")
		}, want: []string(nil), err: "unable to list keys k*: "},
		{name: "ScanKeys", call: func() (any, error) {
			return c.ScanKeys(ctx, "k*", 10)
		}, want: []string(nil), err: "unable to scan keys: "},
		{name: "Exists", call: func() (any, error) {
			return c.Exists(ctx, "k")
		}, want: false, err: "unable to check if key k exists: "},
		{name: "Expire", call: func() (any, error) {
			return c.Expire(ctx, "k", time.Minute)
		}, want: false, err: "unable to set expiration for key k: "},
		{name: "TTL", call: func() (any, error) {
			return c.TTL(ctx, "k")
		}, want: time.Duration(0), err: "unable to get TTL for key k: "},
		{name: "Ping", call: func() (any, error) {
			return nil, c.Ping(ctx)
		}, err: "unable to ping redis: "},
		{name: "TryLock", call: func() (any, error) {
			token, remaining, err := c.TryLock(ctx, "k", time.Second)
			return []any{token, remaining}, err
		}, want: []any{"", time.Duration(0)}, err: "failed to acquire lock for key: k: "},
		{name: "ReleaseLock", call: func() (any, error) {
			return c.ReleaseLock(ctx, "k", "token")
		}, want: false, err: "failed to release lock for key: k: "},
		{name: "IsLocked", call: func() (any, error) {
			return c.IsLocked(ctx, "k")
		}, want: false, err: "failed to check lock for key: k: "},
		{name: "TryAcquireRateLimit", call: func() (any, error) {
			allowed, remaining, err := c.TryAcquireRateLimit(ctx, "k", time.Second)
			return []any{allowed, remaining}, err
		}, want: []any{false, time.Duration(0)}, err: "failed to acquire rate limit for key: k: "},
		{name: "GetRateLimitRemainingTime", call: func() (any, error) {
			return c.GetRateLimitRemainingTime(ctx, "k")
		}, want: time.Duration(0), err: "failed to get rate limit TTL for key: k: "},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.call()
			require.EqualError(t, err, tc.err+closed)
			assert.ErrorIs(t, err, redis.ErrClosed)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetSetArguments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// the arguments are checked before any command is sent
	c, err := redisclient.New(&redisclient.Config{Server: unreachableServer})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, c.Close()) })

	var (
		s      string
		nilPtr *string
	)
	for _, tc := range []struct {
		target any
		err    string
	}{
		{target: s, err: "json: Unmarshal(non-pointer string)"},
		{target: nil, err: "json: Unmarshal(nil)"},
		{target: nilPtr, err: "json: Unmarshal(nil *string)"},
	} {
		err = c.Get(ctx, "k", tc.target)
		require.EqualError(t, err, tc.err)
		var invalid *json.InvalidUnmarshalError
		assert.ErrorAs(t, err, &invalid)
	}

	err = c.Set(ctx, "k", make(chan int), time.Minute)
	require.EqualError(t, err, "failed to marshal value: json: unsupported type: chan int")
	var unsupported *json.UnsupportedTypeError
	assert.ErrorAs(t, err, &unsupported)
}

func TestNewRedisClientCredentials(t *testing.T) {
	t.Parallel()
	const server = "redis://urluser:urlpass@127.0.0.1:1/3"

	tcases := []struct {
		name     string
		cfg      redisclient.Config
		user     string
		password string
	}{
		{
			name:     "url credentials",
			cfg:      redisclient.Config{Server: server},
			user:     "urluser",
			password: "urlpass",
		},
		{
			name:     "password and user override the url",
			cfg:      redisclient.Config{Server: server, User: "u", Password: "p"},
			user:     "u",
			password: "p",
		},
		{
			name:     "password overrides the url user too",
			cfg:      redisclient.Config{Server: server, Password: "p"},
			user:     "",
			password: "p",
		},
		{
			name:     "user without password is ignored",
			cfg:      redisclient.Config{Server: server, User: "u"},
			user:     "urluser",
			password: "urlpass",
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rc, err := redisclient.NewRedisClient(&tc.cfg)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, rc.Close()) })

			opts := rc.Options()
			assert.Equal(t, "127.0.0.1:1", opts.Addr)
			assert.Equal(t, 3, opts.DB)
			assert.Equal(t, tc.user, opts.Username)
			assert.Equal(t, tc.password, opts.Password)
			assert.Nil(t, opts.TLSConfig)
			require.NotNil(t, opts.MaintNotificationsConfig)
			assert.Equal(t, maintnotifications.ModeDisabled, opts.MaintNotificationsConfig.Mode)
		})
	}
}

func TestNewRedisClientTLS(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "redis-client.pem")
	keyFile := filepath.Join(dir, "redis-client-key.pem")
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	// ClientTLS enables TLS even for a redis:// URL, with the client
	// certificate and the trusted CA from the files
	rc, err := redisclient.NewRedisClient(&redisclient.Config{
		Server: "redis://127.0.0.1:1/0",
		ClientTLS: &gserver.TLSInfo{
			CertFile:      certFile,
			KeyFile:       keyFile,
			TrustedCAFile: certFile,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, rc.Close()) })

	tlsCfg := rc.Options().TLSConfig
	require.NotNil(t, tlsCfg)
	require.Len(t, tlsCfg.Certificates, 1)
	require.NotNil(t, tlsCfg.Certificates[0].Leaf)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(certPEM))
	assert.True(t, tlsCfg.RootCAs.Equal(roots))
	_, err = tlsCfg.Certificates[0].Leaf.Verify(x509.VerifyOptions{
		Roots:     tlsCfg.RootCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	assert.NoError(t, err, "the client certificate is the one from the files")

	missing := filepath.Join(dir, "missing-ca.pem")
	failed, err := redisclient.NewRedisClient(&redisclient.Config{
		Server: "redis://127.0.0.1:1/0",
		ClientTLS: &gserver.TLSInfo{
			CertFile:      certFile,
			KeyFile:       keyFile,
			TrustedCAFile: missing,
		},
	})
	require.EqualError(t, err, fmt.Sprintf(
		"redis: unable to build TLS configuration: unable to read CA file %s: open %s: no such file or directory",
		missing, missing))
	assert.ErrorIs(t, err, fs.ErrNotExist)
	assert.Nil(t, failed)
}

func TestMarshal(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		name string
		in   any
		want any
		err  string
	}{
		{name: "string as is", in: "text", want: "text"},
		{name: "bytes as is", in: []byte("raw"), want: []byte("raw")},
		{name: "struct as JSON", in: struct {
			A int `json:"a"`
		}{A: 1}, want: `{"a":1}`},
		{name: "number as JSON", in: 42, want: "42"},
		{name: "nil as JSON null", in: nil, want: "null"},
		{name: "unsupported type", in: func() {}, want: "", err: "failed to marshal value: json: unsupported type: func()"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := redisclient.Marshal(tc.in)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUnmarshalStringCmd(t *testing.T) {
	t.Parallel()
	type obj struct {
		A int `json:"a"`
	}
	boom := errors.New("boom")

	tcases := []struct {
		name   string
		cmd    *redis.StringCmd
		target any
		want   any
		err    string
		cause  error
	}{
		{name: "string", cmd: redis.NewStringResult("v", nil), target: new(string), want: "v"},
		{name: "bytes", cmd: redis.NewStringResult("v", nil), target: new([]byte), want: []byte("v")},
		{name: "JSON", cmd: redis.NewStringResult(`{"a":1}`, nil), target: new(obj), want: obj{A: 1}},
		{name: "bytes command error", cmd: redis.NewStringResult("", boom), target: new([]byte), want: []byte(nil), err: "failed to get key: boom", cause: boom},
		{name: "JSON command error", cmd: redis.NewStringResult("", boom), target: new(obj), want: obj{}, err: "failed to get key: boom", cause: boom},
		{name: "invalid JSON", cmd: redis.NewStringResult("{", nil), target: new(obj), want: obj{}, err: "failed to unmarshal value: unexpected end of JSON input"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := redisclient.UnmarshalStringCmd(tc.cmd, tc.target)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				if tc.cause != nil {
					assert.ErrorIs(t, err, tc.cause)
				}
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, reflect.ValueOf(tc.target).Elem().Interface())
		})
	}
}

func TestIsNotFoundError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{err: nil, want: false},
		{err: redisclient.ErrNotFound, want: true},
		{err: errors.WithMessage(redisclient.ErrNotFound, "get"), want: true},
		// FINDINGS P-095: the substring match is recorded as a defect
		{err: errors.New("user not found"), want: true},
		{err: redis.Nil, want: false},
		{err: errors.New("boom"), want: false},
	} {
		assert.Equal(t, tc.want, redisclient.IsNotFoundError(tc.err), "%v", tc.err)
	}
}
