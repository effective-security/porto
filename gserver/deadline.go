package gserver

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/streamctx"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/limits"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
)

const (
	// deadlineExceededMessage is the status message of a call that reported
	// its expired context.
	deadlineExceededMessage = "request deadline exceeded"
	// canceledMessage is the status message of a call that reported its
	// canceled context.
	canceledMessage = "request canceled"

	// deadlineWriteGrace is how long after Timeouts.Handler a TLS listener
	// resets a gRPC or gRPC-Web stream whose response is still being
	// written (setStreamWriteDeadline): long enough for a handler that
	// returned at the deadline to have its status delivered, short enough
	// to bound a send blocked on the client's flow-control window.
	deadlineWriteGrace = time.Second

	// maxGRPCTimeoutValue is the largest value of a grpc-timeout header: the
	// wire format allows at most 8 digits before the unit.
	maxGRPCTimeoutValue = 100000000 - 1
	// maxGRPCTimeoutLen is the longest valid grpc-timeout header: 8 digits
	// and the unit.
	maxGRPCTimeoutLen = 9
)

// grpcTimeoutUnits maps the unit character of a grpc-timeout header to its
// duration, in the order encodeGRPCTimeout tries them.
var grpcTimeoutUnits = []struct {
	unit     byte
	duration time.Duration
}{
	{'n', time.Nanosecond},
	{'u', time.Microsecond},
	{'m', time.Millisecond},
	{'S', time.Second},
	{'M', time.Minute},
	{'H', time.Hour},
}

// deadlineTapHandle bounds the context of every stream of the native HTTP/2
// transport (plaintext listeners) by timeouts.Handler before the stream is
// created, so the deadline is the transport's: a handler blocked in RecvMsg
// or SendMsg is released with DeadlineExceeded when it expires, which the
// interceptors alone cannot do (streamctx replaces only Context). The
// transport uses the returned context as the stream context and cancels the
// parent when the stream ends, which cancels the child and stops its timer,
// so the cancel function is not needed. The handle runs on the connection's
// I/O goroutine and must not block. The ServeHTTP transport of TLS listeners
// has no tap handle; grpcHandlerFunc caps the grpc-timeout header
// (capGRPCTimeout) and sets a stream write deadline (setStreamWriteDeadline)
// instead.
func deadlineTapHandle(timeouts limits.Timeouts) tap.ServerInHandle {
	return func(ctx context.Context, _ *tap.Info) (context.Context, error) {
		ctx, _ = timeouts.HandlerContext(ctx)
		return ctx, nil
	}
}

// capGRPCTimeout bounds the grpc-timeout header of a gRPC or gRPC-Web
// request served through grpc.Server.ServeHTTP (TLS listeners) by maxTimeout:
// a missing header or one longer than maxTimeout is replaced by maxTimeout
// in the wire format; a shorter one is kept. grpc-go turns the header into
// the stream deadline, so a handler blocked in RecvMsg is released with
// DeadlineExceeded when it expires, while the request context stays alive
// and the handler's status still reaches the client (ending the request
// context instead makes grpc-go close the transport, and the client gets
// Unavailable). A send blocked on the client's flow-control window is not
// released by that deadline; setStreamWriteDeadline covers it. A malformed
// header is left for grpc-go to reject.
func capGRPCTimeout(h http.Header, maxTimeout time.Duration) {
	if v := h.Get(header.GRPCTimeout); v != "" {
		timeout, err := decodeGRPCTimeout(v)
		if err != nil || timeout <= maxTimeout {
			return
		}
	}
	h.Set(header.GRPCTimeout, encodeGRPCTimeout(maxTimeout))
}

// setStreamWriteDeadline bounds the response writes of a gRPC or gRPC-Web
// request served through grpc.Server.ServeHTTP over HTTP/2 (TLS listeners)
// by timeout from now. grpc-go's ServeHTTP transport performs a send as a
// net/http write, which waits for the client's flow-control window without
// watching the stream deadline, so a handler blocked in SendMsg behind a
// client that stopped reading but kept the connection open would outlive
// Timeouts.Handler. When the write deadline expires, net/http resets the
// stream: the blocked send fails with Unavailable, the handler returns, and
// the client sees Internal, as no trailers can follow an aborted write. The
// timeout is therefore Handler plus deadlineWriteGrace, which leaves a
// handler that returned at the deadline time to deliver its status; a
// response still being written after the grace is cut the same way. net/http
// stops the timer when the stream ends. Over HTTP/1.1 (gRPC-Web) the write
// deadline would be the connection's and outlive the request, so callers
// only set it on HTTP/2.
func setStreamWriteDeadline(w http.ResponseWriter, r *http.Request, timeout time.Duration) {
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		logger.ContextKV(r.Context(), xlog.WARNING,
			"reason", "set_write_deadline",
			"path", r.URL.Path,
			"err", err.Error())
	}
}

// encodeGRPCTimeout formats d in the grpc-timeout wire format with the finest
// unit whose value fits in 8 digits, rounding up, as grpc-go does; hours, the
// coarsest unit, always fit.
func encodeGRPCTimeout(d time.Duration) string {
	if d <= 0 {
		return "0n"
	}
	var value int64
	var unit byte
	for _, u := range grpcTimeoutUnits {
		value = int64(d / u.duration)
		if d%u.duration > 0 {
			value++
		}
		unit = u.unit
		if value <= maxGRPCTimeoutValue {
			break
		}
	}
	return strconv.FormatInt(value, 10) + string(unit)
}

// decodeGRPCTimeout parses the grpc-timeout wire format (up to 8 digits and
// a unit among n, u, m, S, M, H) as grpc-go does; a value that overflows
// time.Duration is clamped to math.MaxInt64.
func decodeGRPCTimeout(s string) (time.Duration, error) {
	size := len(s)
	if size < 2 || size > maxGRPCTimeoutLen {
		return 0, errors.Newf("invalid grpc-timeout %q", s)
	}
	var unit time.Duration
	for _, u := range grpcTimeoutUnits {
		if u.unit == s[size-1] {
			unit = u.duration
			break
		}
	}
	if unit == 0 {
		return 0, errors.Newf("invalid grpc-timeout unit %q", s)
	}
	value, err := strconv.ParseUint(s[:size-1], 10, 64)
	if err != nil {
		return 0, errors.Wrapf(err, "invalid grpc-timeout %q", s)
	}
	if value > math.MaxInt64/uint64(unit) {
		return time.Duration(math.MaxInt64), nil
	}
	return time.Duration(value) * unit, nil
}

// deadlineUnaryInterceptor bounds each call's context by timeouts.Handler
// (see limits.Timeouts.HandlerContext): the handler's context expires after
// it unless the client asked for an earlier deadline, which is kept. The
// transport stream context is already bounded (deadlineTapHandle,
// capGRPCTimeout), so this is a cheap second bound that does not depend on
// the transport. grpc-go decodes the request before any interceptor runs,
// so the bound starts after the decode. A call that reports its expired or
// canceled context with a plain error is answered with DeadlineExceeded or
// Canceled (deadlineError), so clients, logs and metrics see that code
// instead of Unknown.
func deadlineUnaryInterceptor(timeouts limits.Timeouts) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, cancel := timeouts.HandlerContext(ctx)
		defer cancel()
		res, err := handler(ctx, req)
		return res, deadlineError(ctx, err)
	}
}

// deadlineStreamInterceptor is deadlineUnaryInterceptor for streams: the
// handler sees the bounded context through streamctx.WithContext, and a
// plain context error it returns becomes DeadlineExceeded. Blocked stream
// I/O is released by the transport deadline (deadlineTapHandle,
// capGRPCTimeout, setStreamWriteDeadline), not by this context.
func deadlineStreamInterceptor(timeouts limits.Timeouts) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, cancel := timeouts.HandlerContext(ss.Context())
		defer cancel()
		return deadlineError(ctx, handler(srv, streamctx.WithContext(ctx, ss)))
	}
}

// deadlineError converts err to the gRPC status of the context error it
// wraps when the call's context is done and err carries no gRPC status: a
// handler that returns its context error, wrapped or not, fails the call
// with DeadlineExceeded or Canceled. The original error is kept as the cause
// for the log line. Any other error, including one that already carries a
// status, is returned unchanged.
func deadlineError(ctx context.Context, err error) error {
	if err == nil || ctx.Err() == nil {
		return err
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return httperror.NewGrpcFromCtx(ctx, codes.DeadlineExceeded, deadlineExceededMessage).WithCause(err)
	case errors.Is(err, context.Canceled):
		return httperror.NewGrpcFromCtx(ctx, codes.Canceled, canceledMessage).WithCause(err)
	}
	return err
}
