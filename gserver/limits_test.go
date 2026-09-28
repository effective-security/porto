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

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/tests/mockappcontainer"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/limits"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			srv, err := gserver.Start("limits", cfg, container, nil, gserver.WithMiddleware(func(_ http.Handler) http.Handler {
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

				for _, contentType := range []string{header.ApplicationJSON, header.ApplicationGRPC, header.ApplicationGRPCWebProto} {
					req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, scheme+"://"+addr, strings.NewReader(`"abcde"`))
					require.NoError(t, err)
					req.Header.Set(header.ContentType, contentType)
					resp, err := h2Client.Do(req)
					require.NoError(t, err)
					assert.Equal(t, 2, resp.ProtoMajor)
					assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
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
