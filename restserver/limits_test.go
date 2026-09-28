package restserver_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	rest "github.com/effective-security/porto/restserver"
	"github.com/effective-security/porto/tests/testutils"
	"github.com/effective-security/porto/xhttp/header"
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

// decodeURL is a POST route that decodes a JSON body.
const decodeURL = "/v1/decode"

type decodeService struct{}

func (decodeService) Name() string  { return "decode" }
func (decodeService) IsReady() bool { return true }
func (decodeService) Close()        {}

func (decodeService) Register(r rest.Router) {
	r.POST(decodeURL, func(w http.ResponseWriter, r *http.Request, _ rest.Params) {
		var body any
		if marshal.DecodeBody(w, r, &body) != nil {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestDefaultMuxBodyLimit(t *testing.T) {
	t.Parallel()
	addr := testutils.CreateBindAddr("127.0.0.1")
	srv, err := rest.New("test", "127.0.0.1", &serverConfig{BindAddr: addr}, nil)
	require.NoError(t, err)
	srv.WithMaxRequestBody(6).WithCORS(&rest.CORSOptions{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{http.MethodPost},
	})
	srv.AddService(decodeService{})
	require.NoError(t, srv.StartHTTP())
	t.Cleanup(srv.StopHTTP)
	require.Eventually(t, srv.IsReady, 2*time.Second, 10*time.Millisecond)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+addr+decodeURL, strings.NewReader(`"abcde"`))
	require.NoError(t, err)
	req.Header.Set(header.ContentType, header.ApplicationJSON)
	req.Header.Set("Origin", "https://app.example.com")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	// The 413 comes from inside the router's CORS and the correlation handler.
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, resp.Header.Get(header.XCorrelationID))
}
