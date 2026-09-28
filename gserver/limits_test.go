package gserver_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/tests/mockappcontainer"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/limits"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// uploadMethod is a client-streaming RPC that returns the number of bytes
// received; it is registered from a hand-written ServiceDesc.
const uploadMethod = "/porto.test.Upload/Upload"

var uploadServices = map[string]gserver.ServiceFactory{
	"upload": func(server gserver.GServer) any {
		return func() {
			server.AddService(uploadService{})
		}
	},
}

type uploadService struct{}

func (uploadService) Name() string  { return "upload" }
func (uploadService) IsReady() bool { return true }
func (uploadService) Close()        {}

func (uploadService) RegisterGRPC(s *grpc.Server) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "porto.test.Upload",
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Upload",
				ClientStreams: true,
				Handler: func(_ any, stream grpc.ServerStream) error {
					var total int64
					for {
						msg := &wrapperspb.BytesValue{}
						err := stream.RecvMsg(msg)
						if errors.Is(err, io.EOF) {
							return stream.SendMsg(wrapperspb.Int64(total))
						}
						if err != nil {
							return err
						}
						total += int64(len(msg.GetValue()))
					}
				},
			},
		},
	}, uploadService{})
}

// upload sends chunks of size bytes, pausing between them, and returns the
// byte count reported by the server.
func upload(ctx context.Context, conn *grpc.ClientConn, chunks, size int, pause time.Duration) (int64, error) {
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true}, uploadMethod)
	if err != nil {
		return 0, err
	}
	for range chunks {
		// A failed send returns io.EOF; RecvMsg reports the status.
		if stream.SendMsg(wrapperspb.Bytes(make([]byte, size))) != nil {
			break
		}
		time.Sleep(pause)
	}
	if err = stream.CloseSend(); err != nil {
		return 0, err
	}
	total := &wrapperspb.Int64Value{}
	if err = stream.RecvMsg(total); err != nil {
		return 0, err
	}
	return total.GetValue(), nil
}

func TestTLSGRPCStreamLimits(t *testing.T) {
	t.Parallel()
	const readTimeout = 200 * time.Millisecond
	cfg := &gserver.Config{
		ListenURLs: []string{"https://127.0.0.1:0"},
		Services:   []string{"upload"},
		ServerTLS: &gserver.TLSInfo{
			CertFile:      "testdata/test-server.pem",
			KeyFile:       "testdata/test-server-key.pem",
			TrustedCAFile: "testdata/test-server-rootca.pem",
		},
		Timeouts: limits.Timeouts{
			Read: readTimeout,
		},
		MaxRequestBody: 64 * 1024,
	}
	container := mockappcontainer.NewBuilder().WithDiscovery(discovery.New()).Container()
	srv, err := gserver.Start("grpc-limits", cfg, container, uploadServices)
	require.NoError(t, err)
	defer srv.Close()
	addr := srv.(*gserver.Server).Listeners[0].Addr().String()

	clientTLS, err := tlsconfig.NewClientTLSFromFiles("", "", cfg.ServerTLS.TrustedCAFile)
	require.NoError(t, err)
	// Legacy test fixture has no SANs; only test the server transport here.
	clientTLS.InsecureSkipVerify = true
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A client stream may outlive Timeouts.Read, as on plaintext listeners.
	total, err := upload(ctx, conn, 4, 16, readTimeout/2)
	require.NoError(t, err)
	assert.Equal(t, int64(64), total)

	// The stream stays bounded by MaxRequestBody in total.
	_, err = upload(ctx, conn, 8, 16*1024, 0)
	require.Error(t, err)
	// grpc-go reports a failed body read as Unavailable.
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "request body too large")
}

func TestBodyLimitInsideHandlerChain(t *testing.T) {
	t.Parallel()
	enabled := true
	cfg := &gserver.Config{
		ListenURLs:     []string{"http://127.0.0.1:0"},
		MaxRequestBody: 6,
		CORS: &gserver.CORS{
			Enabled:        &enabled,
			AllowedOrigins: []string{"*"},
		},
	}
	container := mockappcontainer.NewBuilder().WithDiscovery(discovery.New()).Container()
	srv, err := gserver.Start("limits-chain", cfg, container, nil, gserver.WithMiddleware(func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body any
			if marshal.DecodeBody(w, r, &body) != nil {
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}))
	require.NoError(t, err)
	defer srv.Close()
	addr := srv.(*gserver.Server).Listeners[0].Addr().String()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+addr, strings.NewReader(`"abcde"`))
	require.NoError(t, err)
	req.Header.Set(header.ContentType, header.ApplicationJSON)
	req.Header.Set("Origin", "https://app.example.com")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	// The browser can read the 413, and the response is correlated.
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, resp.Header.Get(header.XCorrelationID))
}

func TestNetworkLimits(t *testing.T) {
	t.Parallel()
	for _, secure := range []bool{false, true} {
		scheme := "http"
		if secure {
			scheme = "https"
		}
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			cfg := &gserver.Config{
				ListenURLs: []string{scheme + "://127.0.0.1:0"},
				Services:   []string{"upload"},
				Timeouts: limits.Timeouts{
					Handshake: 100 * time.Millisecond,
					Header:    150 * time.Millisecond,
					Read:      250 * time.Millisecond,
					Idle:      100 * time.Millisecond,
				},
				MaxRequestBody: 6,
			}
			var clientTLS *tls.Config
			if secure {
				cfg.ServerTLS = &gserver.TLSInfo{
					CertFile:      "testdata/test-server.pem",
					KeyFile:       "testdata/test-server-key.pem",
					TrustedCAFile: "testdata/test-server-rootca.pem",
				}
				var err error
				clientTLS, err = tlsconfig.NewClientTLSFromFiles("", "", cfg.ServerTLS.TrustedCAFile)
				require.NoError(t, err)
				// Legacy test fixture has no SANs; only test the server transport here.
				clientTLS.InsecureSkipVerify = true
				clientTLS.NextProtos = []string{"http/1.1"}
			}
			container := mockappcontainer.NewBuilder().WithDiscovery(discovery.New()).Container()
			srv, err := gserver.Start("limits", cfg, container, uploadServices, gserver.WithMiddleware(func(_ http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var body any
					if marshal.DecodeBody(w, r, &body) != nil {
						return
					}
					w.WriteHeader(http.StatusNoContent)
				})
			}))
			require.NoError(t, err)
			defer srv.Close()
			addr := srv.(*gserver.Server).Listeners[0].Addr().String()
			// No bytes leaves the connection in cmux or the eager TLS handshake.
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			require.NoError(t, err)
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
			_, err = io.ReadAll(conn)
			require.NoError(t, err, "server must close before the client deadline")
			require.NoError(t, conn.Close())

			dial := func() net.Conn {
				var conn net.Conn
				var err error
				if secure {
					conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, clientTLS)
				} else {
					conn, err = net.DialTimeout("tcp", addr, time.Second)
				}
				require.NoError(t, err)
				require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
				return conn
			}
			for _, request := range []string{
				"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ",
				"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\n\r\n\"a",
			} {
				conn := dial()
				_, err := io.WriteString(conn, request)
				require.NoError(t, err)
				_, err = io.ReadAll(conn)
				require.NoError(t, err, "server must close stalled request before client deadline")
				require.NoError(t, conn.Close())
			}
			if secure {
				h2Transport := &http.Transport{
					TLSClientConfig:   clientTLS.Clone(),
					ForceAttemptHTTP2: true,
				}
				defer h2Transport.CloseIdleConnections()
				h2Client := &http.Client{Timeout: 2 * time.Second, Transport: h2Transport}
				// Unknown length must reach the body reader, not the Content-Length check.
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, scheme+"://"+addr, strings.NewReader(`"abcde"`))
				require.NoError(t, err)
				req.ContentLength = -1
				resp, err := h2Client.Do(req)
				require.NoError(t, err)
				assert.Equal(t, 2, resp.ProtoMajor)
				assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
				require.NoError(t, resp.Body.Close())

				// Keep a request body open; the server read deadline must produce
				// a response before the client's two-second request timeout.
				reader, writer := io.Pipe()
				defer reader.Close()
				defer writer.Close()
				req, err = http.NewRequestWithContext(context.Background(), http.MethodPost, scheme+"://"+addr, reader)
				require.NoError(t, err)
				req.ContentLength = 6
				written := make(chan error, 1)
				go func() {
					_, err := io.WriteString(writer, `"a`)
					written <- err
				}()
				resp, err = h2Client.Do(req)
				require.NoError(t, err)
				assert.Equal(t, 2, resp.ProtoMajor)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
				require.NoError(t, resp.Body.Close())
				require.NoError(t, <-written)

				// A known oversized body fails inside the handler chain: JSON
				// handlers answer 413 with a correlation ID, and gRPC callers
				// get a gRPC response instead of JSON.
				for _, tc := range []struct {
					contentType string
					path        string
					status      int
				}{
					{
						contentType: header.ApplicationJSON,
						path:        "/",
						status:      http.StatusRequestEntityTooLarge,
					},
					{
						contentType: header.ApplicationGRPC,
						path:        uploadMethod,
						status:      http.StatusOK,
					},
					{
						contentType: header.ApplicationGRPCWebProto,
						path:        uploadMethod,
						status:      http.StatusOK,
					},
				} {
					req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, scheme+"://"+addr+tc.path, strings.NewReader(`"abcde"`))
					require.NoError(t, err)
					req.Header.Set(header.ContentType, tc.contentType)
					resp, err := h2Client.Do(req)
					require.NoError(t, err)
					assert.Equal(t, 2, resp.ProtoMajor)
					assert.Equal(t, tc.status, resp.StatusCode, tc.contentType)
					if tc.status == http.StatusRequestEntityTooLarge {
						assert.NotEmpty(t, resp.Header.Get(header.XCorrelationID))
					} else {
						assert.True(t, strings.HasPrefix(resp.Header.Get(header.ContentType), header.ApplicationGRPC), tc.contentType)
					}
					require.NoError(t, resp.Body.Close())
				}
			}
			transport := &http.Transport{TLSClientConfig: clientTLS}
			defer transport.CloseIdleConnections()
			client := &http.Client{Timeout: 2 * time.Second, Transport: transport}
			for _, chunked := range []bool{false, true} {
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, scheme+"://"+addr, strings.NewReader(`"abcde"`))
				require.NoError(t, err)
				if chunked {
					req.ContentLength = -1
				}
				resp, err := client.Do(req)
				require.NoError(t, err)
				assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
				require.NoError(t, resp.Body.Close())
			}
		})
	}
}
