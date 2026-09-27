package cache_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingProvider struct {
	cache.Provider
	getErr   error
	setErr   error
	setTTL   time.Duration
	setValue any
	setCount int
}

func (p *recordingProvider) Get(ctx context.Context, key string, value any) error {
	if p.getErr != nil {
		return p.getErr
	}
	return p.Provider.Get(ctx, key, value)
}

func (p *recordingProvider) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	p.setCount++
	p.setTTL = ttl
	p.setValue = value
	if p.setErr != nil {
		return p.setErr
	}
	return p.Provider.Set(ctx, key, value, ttl)
}

func TestGetOrSetWritesWithProviderDefaultTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := &recordingProvider{Provider: cache.NewMemoryProvider("read-through")}
	var value string
	getterCalls := 0
	getter := func() (any, error) {
		getterCalls++
		result := "computed"
		return &result, nil
	}

	err := cache.GetOrSet(ctx, p, "key", &value, getter)
	require.NoError(t, err)
	assert.Equal(t, "computed", value)
	assert.Equal(t, "computed", p.setValue)
	assert.Equal(t, time.Duration(0), p.setTTL)
	assert.Equal(t, 1, p.setCount)

	value = ""
	err = cache.GetOrSet(ctx, p, "key", &value, getter)
	require.NoError(t, err)
	assert.Equal(t, "computed", value)
	assert.Equal(t, 1, getterCalls)
	assert.Equal(t, 1, p.setCount)
}

func TestGetOrSetErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	backendErr := errors.New("backend failed")
	getterErr := errors.New("getter failed")

	t.Run("read error", func(t *testing.T) {
		p := &recordingProvider{Provider: cache.NewMemoryProvider("read-error"), getErr: backendErr}
		var value string
		err := cache.GetOrSet(ctx, p, "key", &value, func() (any, error) {
			t.Fatal("getter called after read error")
			return nil, nil
		})
		require.ErrorIs(t, err, backendErr)
		assert.Zero(t, p.setCount)
	})

	t.Run("getter error", func(t *testing.T) {
		p := &recordingProvider{Provider: cache.NewMemoryProvider("getter-error")}
		var value string
		err := cache.GetOrSet(ctx, p, "key", &value, func() (any, error) {
			return nil, getterErr
		})
		require.ErrorIs(t, err, getterErr)
		assert.Zero(t, p.setCount)
	})

	t.Run("nil getter on miss", func(t *testing.T) {
		p := &recordingProvider{Provider: cache.NewMemoryProvider("nil-getter")}
		var value string
		err := cache.GetOrSet(ctx, p, "key", &value, nil)
		require.EqualError(t, err, "getter is nil")
		assert.Zero(t, p.setCount)
	})

	t.Run("write error", func(t *testing.T) {
		p := &recordingProvider{Provider: cache.NewMemoryProvider("write-error"), setErr: backendErr}
		value := "unchanged"
		err := cache.GetOrSet(ctx, p, "key", &value, func() (any, error) {
			result := "computed"
			return &result, nil
		})
		require.ErrorIs(t, err, backendErr)
		assert.Equal(t, "unchanged", value)
		assert.Equal(t, 1, p.setCount)
		assert.Equal(t, time.Duration(0), p.setTTL)
	})
}

func TestGetOrSetRejectsInvalidValues(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var typedNil *string
	var nilInterface any
	tcases := []struct {
		name   string
		result any
	}{
		{name: "nil"},
		{name: "typed nil", result: typedNil},
		{name: "non-pointer", result: "value"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			p := &recordingProvider{Provider: cache.NewMemoryProvider(tc.name)}
			var value string
			err := cache.GetOrSet(ctx, p, "key", &value, func() (any, error) {
				return tc.result, nil
			})
			var invalid *json.InvalidUnmarshalError
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, reflect.TypeOf(tc.result), invalid.Type)
			assert.Zero(t, p.setCount)
		})
	}

	t.Run("nil interface", func(t *testing.T) {
		p := &recordingProvider{Provider: cache.NewMemoryProvider("nil-interface")}
		var value string
		err := cache.GetOrSet(ctx, p, "key", &value, func() (any, error) {
			return &nilInterface, nil
		})
		require.EqualError(t, err, "getter returned nil value")
		assert.Zero(t, p.setCount)
	})

	t.Run("incompatible type", func(t *testing.T) {
		p := &recordingProvider{Provider: cache.NewMemoryProvider("type-mismatch")}
		var value string
		err := cache.GetOrSet(ctx, p, "key", &value, func() (any, error) {
			result := 42
			return &result, nil
		})
		require.EqualError(t, err, "getter returned int, cannot assign to string")
		assert.Zero(t, p.setCount)
	})

	t.Run("interface destination", func(t *testing.T) {
		p := &recordingProvider{Provider: cache.NewMemoryProvider("interface-destination")}
		var value any
		getterCalled := false
		err := cache.GetOrSet(ctx, p, "key", &value, func() (any, error) {
			getterCalled = true
			result := []byte("computed")
			return &result, nil
		})
		require.EqualError(t, err, "cache miss requires a concrete destination type")
		assert.False(t, getterCalled)
		assert.Nil(t, value)
		assert.Zero(t, p.setCount)
	})
}
