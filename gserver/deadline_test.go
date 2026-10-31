package gserver_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/limits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// handlerTimeout is the Timeouts.Handler of the deadline tests.
	handlerTimeout = time.Second
	// clientTimeout is a client deadline shorter than handlerTimeout.
	clientTimeout = 250 * time.Millisecond
	// deadlineExceededMessage is the status message of a call that reported
	// its expired context.
	deadlineExceededMessage = "request deadline exceeded"
)

// echoHTTPClient returns an HTTP client for the REST and gRPC-Web routes of
// the echo server and the base URL of the server.
func echoHTTPClient(t *testing.T, srv gserver.GServer, serverTLS *gserver.TLSInfo) (*http.Client, string) {
	t.Helper()
	addr := srv.(*gserver.Server).Listeners[0].Addr().String()
	client := &http.Client{Timeout: echoTimeout}
	t.Cleanup(client.CloseIdleConnections)
	if serverTLS == nil {
		return client, "http://" + addr
	}
	clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", serverTLS.TrustedCAFile)
	require.NoError(t, err)
	// the legacy test fixture has no SANs
	clientTLS.InsecureSkipVerify = true
	client.Transport = &http.Transport{
		TLSClientConfig: clientTLS,
		// the TLS listener answers a client without ALPN with HTTP/2 frames
		ForceAttemptHTTP2: true,
	}
	return client, "https://" + addr
}

// getDeadline returns the body of GET deadlinePath: the remaining time of
// the request deadline the REST handler saw, or noDeadline.
func getDeadline(ctx context.Context, t *testing.T, client *http.Client, base string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+deadlinePath, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	return string(body)
}

// assertRemaining checks that text, an echoDeadline or deadlinePath answer,
// is a remaining time within (0, max].
func assertRemaining(t *testing.T, text string, max time.Duration) {
	t.Helper()
	remaining, err := time.ParseDuration(text)
	require.NoError(t, err, "a deadline is expected, got %q", text)
	assert.Greater(t, remaining, time.Duration(0))
	assert.LessOrEqual(t, remaining, max)
}

// TestHandlerTimeout checks that Timeouts.Handler bounds unary and stream
// calls and REST requests on plaintext and TLS listeners: a handler that
// reports its expired context fails the call with DeadlineExceeded, an
// earlier client deadline is kept, and a later or missing one is capped.
func TestHandlerTimeout(t *testing.T) {
	t.Parallel()
	for _, tc := range listenerCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			serverTLS := tc.serverTLS()
			cfg := &gserver.Config{
				ServerTLS: serverTLS,
				Timeouts:  limits.Timeouts{Handler: handlerTimeout},
			}
			svc := newEchoServer()
			srv, conn := startEcho(t, cfg, svc)
			ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
			defer cancel()

			// The server deadline fires first; the handler's wrapped context
			// error becomes DeadlineExceeded.
			start := time.Now()
			_, err := callEcho(ctx, conn, []byte(echoWait))
			elapsed := time.Since(start)
			require.Error(t, err)
			assert.Equal(t, codes.DeadlineExceeded, status.Code(err), "%v", err)
			assert.Equal(t, deadlineExceededMessage, status.Convert(err).Message())
			assert.GreaterOrEqual(t, elapsed, handlerTimeout)
			assert.Less(t, elapsed, echoTimeout)

			// A status returned after the deadline is kept.
			_, err = callEcho(ctx, conn, []byte(echoWaitStatus))
			require.Error(t, err)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)

			// A later client deadline is capped.
			got, err := callEcho(ctx, conn, []byte(echoDeadline))
			require.NoError(t, err)
			assertRemaining(t, string(got), handlerTimeout)

			// A missing client deadline is bounded.
			got, err = callEcho(context.Background(), conn, []byte(echoDeadline))
			require.NoError(t, err)
			assertRemaining(t, string(got), handlerTimeout)

			// An earlier client deadline is kept.
			shortCtx, shortCancel := context.WithTimeout(ctx, clientTimeout)
			got, err = callEcho(shortCtx, conn, []byte(echoDeadline))
			shortCancel()
			require.NoError(t, err)
			assertRemaining(t, string(got), clientTimeout)

			// A server stream ends with DeadlineExceeded.
			stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, blockMethod)
			require.NoError(t, err)
			require.NoError(t, stream.SendMsg(wrapperspb.Bytes(nil)))
			require.NoError(t, stream.CloseSend())
			start = time.Now()
			err = stream.RecvMsg(&wrapperspb.BytesValue{})
			elapsed = time.Since(start)
			require.Error(t, err)
			assert.Equal(t, codes.DeadlineExceeded, status.Code(err), "%v", err)
			assert.Equal(t, deadlineExceededMessage, status.Convert(err).Message())
			assert.Less(t, elapsed, echoTimeout)

			// REST requests are bounded too.
			client, base := echoHTTPClient(t, srv, serverTLS)
			assertRemaining(t, getDeadline(ctx, t, client, base), handlerTimeout)
			shortCtx, shortCancel = context.WithTimeout(ctx, clientTimeout)
			defer shortCancel()
			// the HTTP server does not see the client's deadline, so the
			// server's bound applies
			assertRemaining(t, getDeadline(shortCtx, t, client, base), handlerTimeout)
		})
	}
}

// TestHandlerTimeoutStalledReceive checks that Timeouts.Handler is the
// transport stream deadline on plaintext and TLS listeners: a handler
// blocked in RecvMsg on a client stream whose client stopped sending but
// left its send side open is released with DeadlineExceeded, and the client
// receives that status.
func TestHandlerTimeoutStalledReceive(t *testing.T) {
	t.Parallel()
	for _, tc := range listenerCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &gserver.Config{
				ServerTLS: tc.serverTLS(),
				Timeouts:  limits.Timeouts{Handler: handlerTimeout},
			}
			svc := newEchoServer()
			_, conn := startEcho(t, cfg, svc)
			ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
			defer cancel()

			// the server starts the deadline when the request headers arrive,
			// which NewStream queues before it returns
			start := time.Now()
			stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true}, collectMethod)
			require.NoError(t, err)
			require.NoError(t, stream.SendMsg(wrapperspb.Bytes([]byte("one"))))
			// the send side stays open: the handler waits in RecvMsg

			err = stream.RecvMsg(&wrapperspb.Int32Value{})
			elapsed := time.Since(start)
			require.Error(t, err)
			assert.Equal(t, codes.DeadlineExceeded, status.Code(err), "%v", err)
			assert.GreaterOrEqual(t, elapsed, handlerTimeout)
			assert.Less(t, elapsed, echoTimeout)

			select {
			case err := <-svc.collectErr:
				assert.Equal(t, codes.DeadlineExceeded, status.Code(err), "the server RecvMsg must be released by the deadline: %v", err)
			case <-ctx.Done():
				t.Fatal("the Collect handler did not return")
			}
		})
	}
}

// TestHandlerTimeoutBlockedSend checks that a stream handler blocked in
// SendMsg behind a client that stopped reading, but keeps the connection
// open, is released after Timeouts.Handler on plaintext and TLS listeners.
// The native transport of a plaintext listener fails the send with
// DeadlineExceeded and delivers that status. A TLS listener resets the
// stream shortly after the deadline, since net/http cannot abort a write
// that waits for the client's window and still deliver trailers: the send
// fails with Unavailable and the client stream ends with Internal.
func TestHandlerTimeoutBlockedSend(t *testing.T) {
	t.Parallel()
	for _, tc := range listenerCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			serverTLS := tc.serverTLS()
			cfg := &gserver.Config{
				ServerTLS: serverTLS,
				Timeouts:  limits.Timeouts{Handler: handlerTimeout},
			}
			svc := newEchoServer()
			srv, _ := startEcho(t, cfg, svc)
			conn := dialEcho(t, srv, cfg, grpc.WithInitialWindowSize(floodWindowSize))
			ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
			defer cancel()

			start := time.Now()
			stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, floodMethod)
			require.NoError(t, err)
			require.NoError(t, stream.SendMsg(wrapperspb.Bytes(nil)))
			require.NoError(t, stream.CloseSend())
			// nothing is read: the handler blocks in SendMsg once it has
			// sent floodWindowSize bytes

			serverCode, clientCode := codes.DeadlineExceeded, codes.DeadlineExceeded
			if serverTLS != nil {
				serverCode, clientCode = codes.Unavailable, codes.Internal
			}
			select {
			case err := <-svc.floodErr:
				elapsed := time.Since(start)
				assert.Equal(t, serverCode, status.Code(err), "the server SendMsg must be released after the deadline: %v", err)
				assert.GreaterOrEqual(t, elapsed, handlerTimeout)
			case <-ctx.Done():
				t.Fatal("the Flood handler was not released")
			}

			// the buffered messages are read first, then the end of the stream
			for err == nil {
				err = stream.RecvMsg(&wrapperspb.BytesValue{})
			}
			assert.Equal(t, clientCode, status.Code(err), "%v", err)
		})
	}
}

// TestHandlerTimeoutUnset checks that without Timeouts.Handler a call or
// request is bounded only by the client's deadline.
func TestHandlerTimeoutUnset(t *testing.T) {
	t.Parallel()
	for _, tc := range listenerCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			serverTLS := tc.serverTLS()
			cfg := &gserver.Config{ServerTLS: serverTLS}
			srv, conn := startEcho(t, cfg, newEchoServer())
			ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
			defer cancel()

			got, err := callEcho(context.Background(), conn, []byte(echoDeadline))
			require.NoError(t, err)
			assert.Equal(t, noDeadline, string(got))

			got, err = callEcho(ctx, conn, []byte(echoDeadline))
			require.NoError(t, err)
			assertRemaining(t, string(got), echoTimeout)

			client, base := echoHTTPClient(t, srv, serverTLS)
			assert.Equal(t, noDeadline, getDeadline(ctx, t, client, base))
		})
	}
}

// TestGRPCWebHandlerTimeout checks that a gRPC-Web call on a TLS listener is
// bounded by Timeouts.Handler and answered with DeadlineExceeded.
func TestGRPCWebHandlerTimeout(t *testing.T) {
	t.Parallel()
	serverTLS := testServerTLS()
	cfg := &gserver.Config{
		ServerTLS: serverTLS,
		Timeouts:  limits.Timeouts{Handler: handlerTimeout},
	}
	srv, _ := startEcho(t, cfg, newEchoServer())
	client, base := echoHTTPClient(t, srv, serverTLS)
	ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
	defer cancel()

	payload, err := proto.Marshal(wrapperspb.Bytes([]byte(echoWait)))
	require.NoError(t, err)
	frame := make([]byte, grpcFrameHeaderSize, grpcFrameHeaderSize+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	frame = append(frame, payload...)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+echoMethod, bytes.NewReader(frame))
	require.NoError(t, err)
	req.Header.Set(header.ContentType, header.ApplicationGRPCWebProto)
	start := time.Now()
	resp, err := client.Do(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	elapsed := time.Since(start)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "4", resp.Header.Get(grpcStatusHeader)) // DeadlineExceeded
	assert.Equal(t, deadlineExceededMessage, resp.Header.Get(grpcMessageHeader))
	assert.GreaterOrEqual(t, elapsed, handlerTimeout)
	assert.Less(t, elapsed, echoTimeout)
}
