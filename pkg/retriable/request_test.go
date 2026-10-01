package retriable_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoServer answers every request with its body and reports its
// Content-Length in the X-Request-Length response header.
func echoServer(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		w.Header().Set("X-Request-Length", strconv.FormatInt(r.ContentLength, 10))
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestNewRequest(t *testing.T) {
	t.Parallel()

	tcases := []struct {
		name   string
		method string
		url    string
		body   io.ReadSeeker
		length int64
		err    string
	}{
		{name: "no_body", method: http.MethodGet, url: "https://api.test/v1"},
		{name: "bytes", method: http.MethodPost, url: "https://api.test/v1", body: bytes.NewReader([]byte("12345")), length: 5},
		{name: "string", method: http.MethodPut, url: "https://api.test/v1", body: strings.NewReader("abc"), length: 3},
		// a reader without Len leaves the length unknown
		{name: "unknown_length", method: http.MethodPost, url: "https://api.test/v1", body: io.NewSectionReader(strings.NewReader("abc"), 0, 3)},
		{name: "invalid_url", method: http.MethodGet, url: "https://[::1", err: `parse "https://[::1": missing ']' in host`},
		{name: "invalid_method", method: "bad method", url: "https://api.test/v1", err: `net/http: invalid method "bad method"`},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := retriable.NewRequest(tc.method, tc.url, tc.body)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, r)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.method, r.Method)
			assert.Equal(t, tc.url, r.URL.String())
			assert.Equal(t, tc.length, r.ContentLength)
			// the body is supplied for each attempt by Client.Do
			assert.Nil(t, r.Body)
		})
	}
}

func TestRequestHeaders(t *testing.T) {
	t.Parallel()

	r, err := retriable.NewRequest(http.MethodGet, "https://api.test/v1", nil)
	require.NoError(t, err)
	r.Header.Set("X-Existing", "first")

	same := r.WithHeaders(map[string]string{
		"X-Existing": "second",
		"X-New":      "value",
	}).AddHeader("X-Existing", "third")
	assert.Same(t, r, same)
	assert.Equal(t, []string{"first", "second", "third"}, r.Header.Values("X-Existing"))
	assert.Equal(t, []string{"value"}, r.Header.Values("X-New"))
}

func TestClientRequestBodies(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := echoServer(t, &calls)
	client, err := retriable.New(retriable.ClientConfig{Host: server.URL})
	require.NoError(t, err)

	tcases := []struct {
		name   string
		body   any
		sent   string
		length string
	}{
		{name: "read_seeker", body: strings.NewReader("seeker"), sent: "seeker", length: "6"},
		{name: "reader", body: struct{ io.Reader }{strings.NewReader("reader")}, sent: "reader", length: "6"},
		{name: "bytes", body: []byte("bytes"), sent: "bytes", length: "5"},
		{name: "string", body: "string", sent: "string", length: "6"},
		{name: "json", body: map[string]int{"n": 1}, sent: `{"n":1}`, length: "7"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var w bytes.Buffer
			h, status, err := client.Post(context.Background(), "/echo", tc.body, &w)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, status)
			assert.Equal(t, tc.sent, w.String())
			assert.Equal(t, tc.length, h.Get("X-Request-Length"))
		})
	}
}

func TestClientRequestErrorsBeforeSending(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := echoServer(t, &calls)
	client, err := retriable.New(retriable.ClientConfig{Host: server.URL})
	require.NoError(t, err)
	ctx := context.Background()

	tcases := []struct {
		name   string
		method string
		host   string
		body   any
		err    string
	}{
		{name: "body_read", method: http.MethodPost, host: server.URL, body: iotest.ErrReader(errors.New("read failed")), err: "read failed"},
		{name: "body_encode", method: http.MethodPost, host: server.URL, body: make(chan int), err: "json: unsupported type: chan int"},
		{name: "empty_host", method: http.MethodGet, err: "invalid parameter: host"},
		{name: "invalid_method", method: "bad method", host: server.URL, err: `net/http: invalid method "bad method"`},
	}
	for _, tc := range tcases {
		// not parallel: the server call count is checked at the end
		t.Run(tc.name, func(t *testing.T) {
			h, status, err := client.Request(ctx, tc.method, tc.host, "/echo", tc.body, nil)
			assert.EqualError(t, err, tc.err)
			assert.Nil(t, h)
			assert.Zero(t, status)
		})
	}

	h, status, err := client.HeadTo(ctx, "", "/echo")
	assert.EqualError(t, err, "invalid parameter: host")
	assert.Nil(t, h)
	assert.Zero(t, status)

	// a request that cannot be rebuilt for retries fails in Do
	u, err := url.Parse(server.URL + "/echo")
	require.NoError(t, err)
	resp, err := client.Do(&http.Request{Method: "bad method", URL: u, Header: http.Header{}})
	assert.EqualError(t, err, `net/http: invalid method "bad method"`)
	assert.Nil(t, resp)

	assert.Zero(t, calls.Load(), "no request reached the server")
}

func TestClientNilContext(t *testing.T) {
	t.Parallel()

	received := make(chan http.Header, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, err := retriable.New(retriable.ClientConfig{
		Host:    server.URL,
		Request: &retriable.RequestPolicy{Timeout: 5 * time.Second},
	})
	require.NoError(t, err)

	// a nil context is treated as context.Background()
	var nilCtx context.Context
	var out map[string]any
	_, status, err := client.Get(nilCtx, "/", &out)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	<-received

	ctx := retriable.WithHeaders(nilCtx, map[string]string{"X-Call": "with-headers"})
	require.NotNil(t, ctx)
	_, _, err = client.Get(ctx, "/", &out)
	require.NoError(t, err)
	assert.Equal(t, "with-headers", (<-received).Get("X-Call"))

	in := httptest.NewRequest(http.MethodGet, "/in", nil)
	in.Header.Set("X-Forward", "propagated")
	ctx = retriable.PropagateHeadersFromRequest(nilCtx, in, "X-Forward", "X-Absent")
	require.NotNil(t, ctx)
	_, _, err = client.Get(ctx, "/", &out)
	require.NoError(t, err)
	h := <-received
	assert.Equal(t, "propagated", h.Get("X-Forward"))
	assert.Empty(t, h.Values("X-Absent"))
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestDecodeResponseWriterError(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := echoServer(t, &calls)
	client, err := retriable.New(retriable.ClientConfig{Host: server.URL})
	require.NoError(t, err)

	h, status, err := client.Post(context.Background(), "/echo", "payload", failingWriter{})
	assert.EqualError(t, err, "unable to read body response to (retriable_test.failingWriter) type: write failed")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "7", h.Get("X-Request-Length"))
}

type nilTokenIdentity struct{}

func (nilTokenIdentity) GetCallerIdentity(context.Context) (*credentials.Token, error) {
	return nil, nil
}

func TestCallerIdentityWithoutToken(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := echoServer(t, &calls)
	client, err := retriable.New(retriable.ClientConfig{Host: server.URL},
		retriable.WithCallerIdentity(nilTokenIdentity{}))
	require.NoError(t, err)

	_, status, err := client.Get(context.Background(), "/echo", nil)
	assert.EqualError(t, err, "caller identity returned no token")
	assert.Zero(t, status)
	assert.Zero(t, calls.Load())
}

func TestShouldRetryTransportErrors(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("connection refused")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	noConnectionRetry := retriable.DefaultPolicy()
	delete(noConnectionRetry.Retries, 0)

	tcases := []struct {
		name   string
		ctx    context.Context
		policy retriable.Policy
		reason string
	}{
		{name: "canceled", ctx: canceled, policy: retriable.DefaultPolicy(), reason: retriable.Cancelled},
		{name: "deadline", ctx: expired, policy: retriable.DefaultPolicy(), reason: retriable.DeadlineExceeded},
		{name: "no_entry", ctx: context.Background(), policy: noConnectionRetry, reason: retriable.NonRetriableError},
		{name: "default", ctx: context.Background(), policy: retriable.DefaultPolicy(), reason: "connection"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "https://api.test/v1", nil).WithContext(tc.ctx)
			should, _, reason := tc.policy.ShouldRetry(r, nil, transportErr, 0)
			assert.Equal(t, tc.reason, reason)
			assert.Equal(t, tc.reason == "connection", should)
		})
	}
}
