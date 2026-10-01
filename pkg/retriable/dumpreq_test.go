package retriable_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type closeErrorBody struct {
	io.Reader
}

func (closeErrorBody) Close() error {
	return errors.New("close failed")
}

func TestDumpRequestOutNilRequest(t *testing.T) {
	t.Parallel()

	dump, err := retriable.DumpRequestOut(nil, true)
	assert.EqualError(t, err, "request is nil")
	assert.Nil(t, dump)
}

func TestDumpRequestOutBodies(t *testing.T) {
	t.Parallel()

	t.Run("no_body", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.test/path", nil)
		require.NoError(t, err)
		req.Body = http.NoBody
		dump, err := retriable.DumpRequestOut(req, true)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(dump), "POST /path HTTP/1.1\r\nHost: example.test\r\n"), string(dump))
		assert.True(t, strings.HasSuffix(string(dump), "\r\n\r\n"), string(dump))
		assert.Equal(t, http.NoBody, req.Body)
	})

	t.Run("with_body", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.test/path", strings.NewReader("payload"))
		require.NoError(t, err)
		dump, err := retriable.DumpRequestOut(req, true)
		require.NoError(t, err)
		assert.True(t, strings.HasSuffix(string(dump), "\r\n\r\npayload"), string(dump))
		assert.Contains(t, string(dump), "Content-Length: 7\r\n")
		// the body is restored for the caller
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, "payload", string(body))
	})

	t.Run("unknown_length_without_body", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.test/path", nil)
		require.NoError(t, err)
		req.Body = io.NopCloser(strings.NewReader("streamed"))
		req.ContentLength = 0
		dump, err := retriable.DumpRequestOut(req, false)
		require.NoError(t, err)
		assert.Contains(t, string(dump), "Transfer-Encoding: chunked\r\n")
		assert.True(t, strings.HasSuffix(string(dump), "\r\n\r\n"), string(dump))
		assert.NotContains(t, string(dump), "streamed")
		// the body is not read
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, "streamed", string(body))
	})

	t.Run("known_length_without_body", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, "https://example.test/path", strings.NewReader("abc"))
		require.NoError(t, err)
		dump, err := retriable.DumpRequestOut(req, false)
		require.NoError(t, err)
		assert.Contains(t, string(dump), "Content-Length: 3\r\n")
		assert.True(t, strings.HasSuffix(string(dump), "\r\n\r\n"), string(dump))
		assert.NotContains(t, string(dump), "xxx", "the placeholder body is cut off")
	})
}

func TestDumpRequestOutErrors(t *testing.T) {
	t.Parallel()

	tcases := []struct {
		name   string
		body   io.ReadCloser
		header http.Header
		err    string
	}{
		{name: "read", body: io.NopCloser(iotest.ErrReader(errors.New("read failed"))), err: "read failed"},
		{name: "close", body: closeErrorBody{strings.NewReader("payload")}, err: "close failed"},
		{
			name:   "invalid_header",
			body:   io.NopCloser(strings.NewReader("payload")),
			header: http.Header{"X-Bad": {"line\nbreak"}},
			err:    `net/http: invalid header field value for "X-Bad"`,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.test/path", nil)
			require.NoError(t, err)
			req.Body = tc.body
			for k, v := range tc.header {
				req.Header[k] = v
			}
			dump, err := retriable.DumpRequestOut(req, true)
			assert.EqualError(t, err, tc.err)
			assert.Nil(t, dump)
			if tc.header == nil {
				assert.Equal(t, tc.body, req.Body, "a body that fails to drain (read or close) is not replaced")
				return
			}
			// a body read before the transport failed is restored
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.Equal(t, "payload", string(body))
		})
	}
}
