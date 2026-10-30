package gserver

import (
	"context"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDeadlineError(t *testing.T) {
	t.Parallel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	live := context.Background()

	plain := errors.New("backend failed")
	wrappedDeadline := errors.WithMessage(context.DeadlineExceeded, "query")
	wrappedCanceled := errors.Wrap(context.Canceled, "query")
	statusErr := status.Error(codes.FailedPrecondition, "precondition failed")
	apiErr := httperror.NotFound("item")

	t.Run("nil error", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, deadlineError(expired, nil))
	})
	t.Run("context not done", func(t *testing.T) {
		t.Parallel()
		assert.Same(t, wrappedDeadline, deadlineError(live, wrappedDeadline))
	})
	t.Run("status is kept", func(t *testing.T) {
		t.Parallel()
		assert.Same(t, statusErr, deadlineError(expired, statusErr))
		assert.Same(t, apiErr, deadlineError(expired, apiErr))
	})
	t.Run("unrelated error is kept", func(t *testing.T) {
		t.Parallel()
		assert.Same(t, plain, deadlineError(expired, plain))
	})
	t.Run("deadline exceeded", func(t *testing.T) {
		t.Parallel()
		err := deadlineError(expired, wrappedDeadline)
		var apiError *httperror.Error
		require.ErrorAs(t, err, &apiError)
		assert.Equal(t, codes.DeadlineExceeded, apiError.RPCStatus)
		assert.Equal(t, deadlineExceededMessage, apiError.Message)
		assert.Same(t, wrappedDeadline, apiError.Cause())
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
	})
	t.Run("canceled", func(t *testing.T) {
		t.Parallel()
		// a canceled call context reports Canceled even for a wrapped
		// DeadlineExceeded from a downstream call
		err := deadlineError(canceled, wrappedCanceled)
		var apiError *httperror.Error
		require.ErrorAs(t, err, &apiError)
		assert.Equal(t, codes.Canceled, apiError.RPCStatus)
		assert.Equal(t, canceledMessage, apiError.Message)
		assert.Same(t, wrappedCanceled, apiError.Cause())
	})
}

func TestEncodeGRPCTimeout(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{0, "0n"},
		{-time.Second, "0n"},
		{time.Nanosecond, "1n"},
		{99999999 * time.Nanosecond, "99999999n"},
		{100000000 * time.Nanosecond, "100000u"},
		{time.Millisecond + time.Nanosecond, "1000001n"},
		{300 * time.Millisecond, "300000u"},
		{time.Second, "1000000u"},
		{100 * time.Second, "100000m"},
		{2 * time.Minute, "120000m"},
		{30 * time.Hour, "108000S"},
		{100000 * time.Hour, "6000000M"},
		{time.Duration(math.MaxInt64), "2562048H"},
	} {
		assert.Equal(t, tc.want, encodeGRPCTimeout(tc.d), "%s", tc.d)
	}
}

func TestDecodeGRPCTimeout(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		s       string
		want    time.Duration
		wantErr string
	}{
		{s: "1n", want: time.Nanosecond},
		{s: "250u", want: 250 * time.Microsecond},
		{s: "300m", want: 300 * time.Millisecond},
		{s: "30S", want: 30 * time.Second},
		{s: "2M", want: 2 * time.Minute},
		{s: "1H", want: time.Hour},
		{s: "99999999H", want: time.Duration(math.MaxInt64)},
		{s: "", wantErr: `invalid grpc-timeout ""`},
		{s: "S", wantErr: `invalid grpc-timeout "S"`},
		{s: "123456789S", wantErr: `invalid grpc-timeout "123456789S"`},
		{s: "30s", wantErr: `invalid grpc-timeout unit "30s"`},
		{s: "3x0S", wantErr: `invalid grpc-timeout "3x0S"`},
		{s: "-1S", wantErr: `invalid grpc-timeout "-1S"`},
	} {
		got, err := decodeGRPCTimeout(tc.s)
		if tc.wantErr != "" {
			assert.ErrorContains(t, err, tc.wantErr, "%q", tc.s)
			continue
		}
		require.NoError(t, err, "%q", tc.s)
		assert.Equal(t, tc.want, got, "%q", tc.s)
	}
}

func TestCapGRPCTimeout(t *testing.T) {
	t.Parallel()
	const maxTimeout = 2 * time.Minute
	for _, tc := range []struct {
		name string
		in   string // "" for no header
		want string
	}{
		{name: "missing header is set", want: "120000m"},
		{name: "shorter client deadline is kept", in: "30S", want: "30S"},
		{name: "equal client deadline is kept", in: "2M", want: "2M"},
		{name: "longer client deadline is capped", in: "1H", want: "120000m"},
		{name: "malformed header is left to grpc-go", in: "30s", want: "30s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			if tc.in != "" {
				h.Set(header.GRPCTimeout, tc.in)
			}
			capGRPCTimeout(h, maxTimeout)
			assert.Equal(t, tc.want, h.Get(header.GRPCTimeout))
		})
	}
}

func TestShutdownTimeout(t *testing.T) {
	t.Parallel()
	var cfg Config
	assert.Equal(t, defaultShutdownTimeout, cfg.shutdownTimeout())
	cfg.Timeout.Request = time.Second
	assert.Equal(t, time.Second, cfg.shutdownTimeout(), "the former name is read when shutdown is zero")
	cfg.Timeout.Shutdown = 2 * time.Second
	assert.Equal(t, 2*time.Second, cfg.shutdownTimeout(), "shutdown wins")
	cfg.Timeout.Request = 0
	assert.Equal(t, 2*time.Second, cfg.shutdownTimeout())
}
