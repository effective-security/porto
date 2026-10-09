package gserver_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"maps"
	"net/http"
	"testing"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// rateLimitMessage is tollbooth's default message for a limited request.
	rateLimitMessage = "You have reached maximum request limit."
	// webOrigin is the CORS origin of the gRPC-Web caller.
	webOrigin = "https://app.example"
	// grpcStatusHeader and grpcMessageHeader hold the status of a
	// trailers-only gRPC or gRPC-Web response.
	grpcStatusHeader  = "Grpc-Status"
	grpcMessageHeader = "Grpc-Message"
	// grpcFrameHeaderSize is the flag byte and the 4-byte length that
	// precede each gRPC message.
	grpcFrameHeaderSize = 5
)

// testServerTLS returns the TLS fixture of the gserver tests.
func testServerTLS() *gserver.TLSInfo {
	return &gserver.TLSInfo{
		CertFile:      "testdata/test-server.pem",
		KeyFile:       "testdata/test-server-key.pem",
		TrustedCAFile: "testdata/test-server-rootca.pem",
	}
}

// listenerCases are the plaintext and TLS listeners startEcho can serve.
var listenerCases = []struct {
	name      string
	serverTLS func() *gserver.TLSInfo
}{
	{
		name:      "plaintext",
		serverTLS: func() *gserver.TLSInfo { return nil },
	},
	{
		name:      "tls",
		serverTLS: testServerTLS,
	},
}

// rateLimit returns an enabled RateLimit of one request per second.
func rateLimit() *gserver.RateLimit {
	enabled := true
	return &gserver.RateLimit{
		Enabled:           &enabled,
		RequestsPerSecond: 1,
	}
}

// TestGRPCRateLimit checks that RateLimit limits gRPC calls on plaintext
// listeners, where cmux sends them past the HTTP handler, and on TLS
// listeners, where each call draws one token: per client IP that a
// trusted proxy forwards and per method path, answered with
// ResourceExhausted.
func TestGRPCRateLimit(t *testing.T) {
	t.Parallel()
	for _, tc := range listenerCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &gserver.Config{
				ServerTLS:         tc.serverTLS(),
				TrustedProxyCIDRs: []string{"127.0.0.0/8"},
				RateLimit:         rateLimit(),
			}
			svc := newEchoServer()
			_, conn := startEcho(t, cfg, svc)
			ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
			defer cancel()
			from := func(client string) context.Context {
				return metadata.AppendToOutgoingContext(ctx, header.XForwardedFor, client)
			}

			_, err := callEcho(from("203.0.113.1"), conn, []byte("a"))
			require.NoError(t, err)
			_, err = callEcho(from("203.0.113.2"), conn, []byte("b"))
			require.NoError(t, err, "a distinct client has its own bucket")
			_, err = callEcho(from("203.0.113.1"), conn, []byte("c"))
			assert.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)
			assert.Equal(t, rateLimitMessage, status.Convert(err).Message())
			assert.EqualValues(t, 2, svc.calls.Load())

			got, err := callWatch(from("203.0.113.1"), conn, "tick")
			require.NoError(t, err, "a method path has its own bucket")
			assert.Len(t, got, watchCount)
			_, err = callWatch(from("203.0.113.1"), conn, "tick")
			assert.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)
		})
	}
}

// TestGRPCRateLimitBeforeValidation checks that a unary call draws a token
// before Validate runs, so requests that fail or panic in Validate are
// limited too, on plaintext and TLS listeners.
func TestGRPCRateLimitBeforeValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range listenerCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &gserver.Config{
				ServerTLS: tc.serverTLS(),
				RateLimit: rateLimit(),
			}
			svc := newEchoServer()
			_, conn := startEcho(t, cfg, svc)
			ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
			defer cancel()

			var got []codes.Code
			for _, value := range []string{echoInvalid, echoInvalid, echoValidatePanic, "valid"} {
				_, err := callEcho(ctx, conn, []byte(value))
				got = append(got, status.Code(err))
			}
			assert.Equal(t, []codes.Code{
				codes.InvalidArgument,
				codes.ResourceExhausted,
				codes.ResourceExhausted,
				codes.ResourceExhausted,
			}, got)
			assert.Zero(t, svc.calls.Load())
		})
	}
}

// TestGRPCRateLimitMetrics checks that a limited gRPC call is counted by
// the gRPC metrics with ResourceExhausted, like any other failed call, and
// not by the HTTP metrics. It installs the process-global metrics sink, so
// it is not parallel.
func TestGRPCRateLimitMetrics(t *testing.T) {
	for _, tc := range listenerCases {
		t.Run(tc.name, func(t *testing.T) {
			counts := newGRPCMetricsSink(t)
			cfg := &gserver.Config{
				ServerTLS: tc.serverTLS(),
				RateLimit: rateLimit(),
			}
			_, conn := startEcho(t, cfg, newEchoServer())
			ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
			defer cancel()

			_, err := callEcho(ctx, conn, []byte("a"))
			require.NoError(t, err)
			_, err = callEcho(ctx, conn, []byte("b"))
			require.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)

			want := rpcMetric(echoMethod, codes.OK)
			maps.Copy(want, rpcMetric(echoMethod, codes.ResourceExhausted))
			assert.Equal(t, want, counts())
		})
	}
}

// TestGRPCWebRateLimit checks that on a TLS listener a limited gRPC-Web
// call gets a ResourceExhausted gRPC-Web response with the CORS headers,
// and a limited REST request gets 429 with a correlation ID.
func TestGRPCWebRateLimit(t *testing.T) {
	t.Parallel()
	enabled := true
	cfg := &gserver.Config{
		ServerTLS: testServerTLS(),
		CORS: &gserver.CORS{
			Enabled:        &enabled,
			AllowedOrigins: []string{webOrigin},
		},
		RateLimit: rateLimit(),
	}
	srv, _ := startEcho(t, cfg, newEchoServer())
	base := "https://" + srv.(*gserver.Server).Listeners[0].Addr().String()
	clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", cfg.ServerTLS.TrustedCAFile)
	require.NoError(t, err)
	// the legacy test fixture has no SANs
	clientTLS.InsecureSkipVerify = true
	client := &http.Client{
		Timeout: echoTimeout,
		Transport: &http.Transport{
			TLSClientConfig: clientTLS,
			// the TLS listener answers a client without ALPN with HTTP/2 frames
			ForceAttemptHTTP2: true,
		},
	}
	t.Cleanup(client.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), echoTimeout)
	defer cancel()

	payload, err := proto.Marshal(wrapperspb.Bytes([]byte("hi")))
	require.NoError(t, err)
	frame := make([]byte, grpcFrameHeaderSize, grpcFrameHeaderSize+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	frame = append(frame, payload...)

	do := func(method, path string, body []byte, contentType string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		require.NoError(t, err)
		if contentType != "" {
			req.Header.Set(header.ContentType, contentType)
			req.Header.Set(header.Origin, webOrigin)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp
	}

	first := do(http.MethodPost, echoMethod, frame, header.ApplicationGRPCWebProto)
	assert.Equal(t, http.StatusOK, first.StatusCode)
	assert.Empty(t, first.Header.Get(grpcStatusHeader), "an admitted call sends its status in the body")
	second := do(http.MethodPost, echoMethod, frame, header.ApplicationGRPCWebProto)
	assert.Equal(t, http.StatusOK, second.StatusCode)
	assert.Equal(t, "8", second.Header.Get(grpcStatusHeader)) // ResourceExhausted
	assert.Equal(t, rateLimitMessage, second.Header.Get(grpcMessageHeader))
	assert.Equal(t, webOrigin, second.Header.Get("Access-Control-Allow-Origin"))

	// the echo service has no REST routes
	assert.Equal(t, http.StatusNotFound, do(http.MethodGet, "/v1/items", nil, "").StatusCode)
	rejected := do(http.MethodGet, "/v1/items", nil, "")
	assert.Equal(t, http.StatusTooManyRequests, rejected.StatusCode)
	assert.NotEmpty(t, rejected.Header.Get(header.XCorrelationID))
}
