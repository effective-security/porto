package marshal_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/limits"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingReader records how many body bytes the server read.
type countingReader struct {
	io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	c.read += n
	return n, err
}

func TestBodyLimits(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		body          string
		limit         int64
		unknownLength bool
		status        int
	}{
		{"at limit", `"abcd"`, 6, false, http.StatusOK},
		{"unknown length at limit", `"abcd"`, 6, true, http.StatusOK},
		{"known overflow", `"abcde"`, 6, false, http.StatusRequestEntityTooLarge},
		{"chunked overflow", `"abcde"`, 6, true, http.StatusRequestEntityTooLarge},
		{"trailing overflow", `{}        `, 6, true, http.StatusRequestEntityTooLarge},
		{"invalid json", `!`, 6, true, http.StatusBadRequest},
		{"disabled", `"abcdef"`, -1, true, http.StatusOK},
		{"raised", `"` + strings.Repeat("x", int(limits.DefaultMaxRequestBody)) + `"`, limits.DefaultMaxRequestBody + 2, true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := &countingReader{Reader: strings.NewReader(tc.body)}
			r := httptest.NewRequest(http.MethodPost, "/", body)
			r.ContentLength = int64(len(tc.body))
			if tc.unknownLength {
				r.ContentLength = -1
			}
			w := httptest.NewRecorder()
			called := false
			h := marshal.LimitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				var value any
				err := marshal.DecodeBody(w, r, &value)
				if tc.status == http.StatusOK {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					if tc.status == http.StatusRequestEntityTooLarge {
						var overflow *http.MaxBytesError
						require.True(t, errors.As(err, &overflow))
						assert.Equal(t, tc.limit, overflow.Limit)
					}
				}
			}), tc.limit)
			h.ServeHTTP(w, r)
			assert.True(t, called, "the limiter must not answer for the handler")
			assert.Equal(t, tc.status, w.Code)
			if tc.status == http.StatusRequestEntityTooLarge && !tc.unknownLength {
				assert.Zero(t, body.read, "known oversized bodies must not be read")
			}
			if tc.status == http.StatusRequestEntityTooLarge {
				assert.Contains(t, w.Body.String(), `"code":"request_too_large"`)
			}
		})
	}
}

func TestLimitRequestBodyWritesNoResponse(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("1234567"))
	w := httptest.NewRecorder()
	h := marshal.LimitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		var overflow *http.MaxBytesError
		require.ErrorAs(t, err, &overflow)
		assert.Equal(t, int64(6), overflow.Limit)
		assert.Empty(t, body, "a known oversized body fails before it is read")
		require.NoError(t, r.Body.Close())
		w.WriteHeader(http.StatusNoContent)
	}), 6)
	h.ServeHTTP(w, r)
	// The handler, not the limiter, chooses the response.
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestDecodeBodyDisabledLimitLeavesTrailingBody(t *testing.T) {
	t.Parallel()
	reader, writer := io.Pipe()
	defer reader.Close()
	go func() {
		// The body stays open after the JSON value, like a streaming client.
		_, _ = io.WriteString(writer, `{} `)
	}()
	r := httptest.NewRequest(http.MethodPost, "/", reader)
	r.ContentLength = -1
	w := httptest.NewRecorder()
	h := marshal.LimitRequestBody(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var value map[string]any
		require.NoError(t, marshal.DecodeBody(w, r, &value))
		assert.Empty(t, value)
	}), -1)
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDecodeBodyDefaultLimit(t *testing.T) {
	t.Parallel()
	payload := `"` + strings.Repeat("x", int(limits.DefaultMaxRequestBody)) + `"`
	for _, unknownLength := range []bool{false, true} {
		body := &countingReader{Reader: strings.NewReader(payload)}
		r := httptest.NewRequest(http.MethodPost, "/", body)
		r.ContentLength = int64(len(payload))
		if unknownLength {
			r.ContentLength = -1
		}
		w := httptest.NewRecorder()
		var value string
		err := marshal.DecodeBody(w, r, &value)
		var overflow *http.MaxBytesError
		require.ErrorAs(t, err, &overflow)
		assert.Equal(t, int64(limits.DefaultMaxRequestBody), overflow.Limit)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
		if !unknownLength {
			assert.Zero(t, body.read, "known oversized bodies must not be read")
		}
	}
}

func TestLimitRequestBodyRawReader(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("1234567"))
	r.ContentLength = -1
	h := marshal.LimitRequestBody(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		var overflow *http.MaxBytesError
		require.ErrorAs(t, err, &overflow)
		assert.Equal(t, "123456", string(body))
	}), 6)
	h.ServeHTTP(httptest.NewRecorder(), r)
}
