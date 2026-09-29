package redisclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRemainingTTL(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		pttl time.Duration
		want time.Duration
	}{
		// go-redis reports PTTL -2 (missing) and -1 (no expiry) as raw nanoseconds
		{pttl: -2, want: 0},
		{pttl: -1, want: 0},
		// the key still exists during its last millisecond
		{pttl: 0, want: time.Millisecond},
		{pttl: time.Millisecond, want: time.Millisecond},
		{pttl: 1500 * time.Millisecond, want: 1500 * time.Millisecond},
	}
	for _, tc := range tcases {
		assert.Equal(t, tc.want, remainingTTL(tc.pttl), tc.pttl)
	}
}
