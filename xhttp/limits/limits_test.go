package limits_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/limits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{"handler has no default", limits.Timeouts{Handler: time.Minute}, limits.Timeouts{
			Header:    10 * time.Second,
			Read:      30 * time.Second,
			Idle:      60 * time.Second,
			Handshake: 10 * time.Second,
			Handler:   time.Minute,
		}},
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

func TestHandlerContext(t *testing.T) {
	t.Parallel()
	const handler = 200 * time.Millisecond
	for _, tc := range []struct {
		name    string
		handler time.Duration
		parent  time.Duration // deadline of the parent context, zero for none
		// want is the expected remaining time, zero for no deadline
		want time.Duration
	}{
		{name: "zero leaves the context unbounded"},
		{name: "negative leaves the context unbounded", handler: -1},
		{name: "zero keeps the client deadline", parent: time.Second, want: time.Second},
		{name: "bounds a context without deadline", handler: handler, want: handler},
		{name: "keeps an earlier client deadline", handler: handler, parent: 50 * time.Millisecond, want: 50 * time.Millisecond},
		{name: "caps a later client deadline", handler: handler, parent: time.Second, want: handler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := context.Background()
			if tc.parent > 0 {
				var cancel context.CancelFunc
				parent, cancel = context.WithTimeout(parent, tc.parent)
				defer cancel()
			}
			start := time.Now()
			ctx, cancel := limits.Timeouts{Handler: tc.handler}.HandlerContext(parent)
			defer cancel()
			deadline, ok := ctx.Deadline()
			if tc.want == 0 {
				assert.False(t, ok, "no deadline expected")
				assert.Equal(t, parent, ctx, "the parent context is returned unchanged")
				return
			}
			require.True(t, ok, "a deadline is expected")
			remaining := time.Until(deadline)
			assert.LessOrEqual(t, remaining, tc.want)
			assert.Greater(t, remaining, tc.want-time.Since(start)-50*time.Millisecond)
		})
	}
}

func TestHandlerContextExpires(t *testing.T) {
	t.Parallel()
	ctx, cancel := limits.Timeouts{Handler: 20 * time.Millisecond}.HandlerContext(context.Background())
	defer cancel()
	select {
	case <-ctx.Done():
		assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("the context did not expire")
	}
}

// deadlineHandler writes the remaining time of the request deadline, or
// "none".
type deadlineHandler struct{}

func (deadlineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	deadline, ok := r.Context().Deadline()
	if !ok {
		_, _ = io.WriteString(w, "none")
		return
	}
	_, _ = io.WriteString(w, time.Until(deadline).String())
}

func TestApplyHandler(t *testing.T) {
	t.Parallel()
	const handler = 300 * time.Millisecond
	inner := deadlineHandler{}
	t.Run("unset returns the handler itself", func(t *testing.T) {
		t.Parallel()
		for _, timeout := range []time.Duration{0, -1} {
			assert.Equal(t, inner, limits.Timeouts{Handler: timeout}.ApplyHandler(inner))
		}
		rec := httptest.NewRecorder()
		limits.Timeouts{}.ApplyHandler(inner).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, "none", rec.Body.String())
	})
	t.Run("bounds the request context", func(t *testing.T) {
		t.Parallel()
		wrapped := limits.Timeouts{Handler: handler}.ApplyHandler(inner)
		_, same := wrapped.(deadlineHandler)
		assert.False(t, same, "a positive Handler wraps the handler")
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		remaining, err := time.ParseDuration(rec.Body.String())
		require.NoError(t, err)
		assert.Greater(t, remaining, time.Duration(0))
		assert.LessOrEqual(t, remaining, handler)
	})
	t.Run("keeps an earlier client deadline", func(t *testing.T) {
		t.Parallel()
		const client = 50 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), client)
		defer cancel()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
		limits.Timeouts{Handler: handler}.ApplyHandler(inner).ServeHTTP(rec, req)
		remaining, err := time.ParseDuration(rec.Body.String())
		require.NoError(t, err)
		assert.LessOrEqual(t, remaining, client)
	})
}
