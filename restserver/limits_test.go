package restserver_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	rest "github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/effective-security/porto/xhttp/limits"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type limitsMux struct{}

func (limitsMux) NewMux() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body any
		if marshal.DecodeBody(w, r, &body) != nil {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestNetworkLimits(t *testing.T) {
	t.Parallel()
	addr := testutils.CreateBindAddr("127.0.0.1")
	srv, err := rest.New("test", "127.0.0.1", &serverConfig{BindAddr: addr}, nil)
	require.NoError(t, err)
	srv.WithTimeouts(limits.Timeouts{
		Header: 100 * time.Millisecond,
		Read:   200 * time.Millisecond,
		Idle:   100 * time.Millisecond,
	}).WithMaxRequestBody(6)
	srv.WithMuxFactory(limitsMux{})
	require.NoError(t, srv.StartHTTP())
	t.Cleanup(srv.StopHTTP)

	for _, tc := range []struct{ name, request string }{
		{"partial headers", "GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: "},
		{"partial body", "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\n\r\n\"a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
			_, err = io.WriteString(conn, tc.request)
			require.NoError(t, err)
			_, err = io.ReadAll(conn)
			require.NoError(t, err, "server must close before the client deadline")
		})
	}
	client := &http.Client{Timeout: 2 * time.Second}
	for _, chunked := range []bool{false, true} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+addr, strings.NewReader(`"abcde"`))
		require.NoError(t, err)
		if chunked {
			req.ContentLength = -1
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	}
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	_, err = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}")
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	_, err = reader.ReadByte()
	require.ErrorIs(t, err, io.EOF, "idle keepalive should close before the client deadline")
}

func TestDefaultMuxBodyLimit(t *testing.T) {
	t.Parallel()
	srv, err := rest.New("test", "127.0.0.1", &serverConfig{BindAddr: "127.0.0.1:0"}, nil)
	require.NoError(t, err)
	srv.WithMaxRequestBody(6)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`"abcde"`))
	w := httptest.NewRecorder()
	srv.NewMux().ServeHTTP(w, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}
