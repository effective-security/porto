package cache

import (
	"context"
	"testing"
	"time"

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

	//time.Sleep(5 * time.Millisecond)
	NowFunc = func() time.Time { return base.Add(2 * time.Millisecond) }

	p.CleanExpired(ctx)

	var out string
	assert.NoError(t, p.Get(ctx, "live", &out))
	assert.Equal(t, "v", out)
	assert.True(t, IsNotFoundError(p.Get(ctx, "dead", &out)))
	keys, err := p.Keys(ctx, "*")
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}
