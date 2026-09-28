package limits_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/limits"
	"github.com/stretchr/testify/assert"
)

func TestTimeoutDefaultsAndOverrides(t *testing.T) {
	t.Parallel()
	overrides := limits.Timeouts{
		Header:    time.Second,
		Read:      time.Minute,
		Idle:      2 * time.Minute,
		Handshake: 3 * time.Second,
	}
	disabled := limits.Timeouts{
		Header:    -1,
		Read:      -1,
		Idle:      -1,
		Handshake: -1,
	}
	for _, tc := range []struct {
		name                 string
		configured, expected limits.Timeouts
	}{
		{"defaults", limits.Timeouts{}, limits.Timeouts{
			Header:    10 * time.Second,
			Read:      30 * time.Second,
			Idle:      60 * time.Second,
			Handshake: 10 * time.Second,
		}},
		{"overrides", overrides, overrides},
		{"disabled", disabled, disabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.configured.WithDefaults())
			var srv http.Server
			tc.configured.ApplyHTTP(&srv)
			assert.Equal(t, tc.expected.Header, srv.ReadHeaderTimeout)
			assert.Equal(t, tc.expected.Read, srv.ReadTimeout)
			assert.Equal(t, tc.expected.Idle, srv.IdleTimeout)
			assert.Zero(t, srv.WriteTimeout, "streaming writes have no imposed deadline")
		})
	}
}
