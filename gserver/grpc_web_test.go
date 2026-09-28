package gserver

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"encoding/base64"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrpcWebResponse_Header(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)

	headers := g.Header()
	require.NotNil(t, headers)
	assert.Equal(t, 0, len(headers))
}

func TestGrpcWebResponse_Write(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)

	data := []byte("test data")
	n, err := g.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, resp.Body.Bytes())
}

func TestGrpcWebResponse_WriteHeader(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)

	g.WriteHeader(http.StatusAccepted)
	assert.Equal(t, http.StatusAccepted, resp.Code)
}

func TestGrpcWebResponse_Flush(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)

	g.Flush()
	assert.Equal(t, 200, resp.Code)
}

func TestGrpcWebResponse_PrepareHeadersJSON(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)

	g.headers.Set("Content-Type", "application/json")
	g.exposeHeaders = true
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, "application/json", h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_PrepareHeaders(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)

	g.headers.Set("Content-Type", "application/grpc-web+proto")
	g.exposeHeaders = true
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, "application/grpc-web+proto", h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_ExposedHeadersMerge(t *testing.T) {
	t.Parallel()
	resp := httptest.NewRecorder()
	resp.Header().Set("Access-Control-Expose-Headers", "X-Custom-Header, GRPC-STATUS, x-custom-header")
	resp.Header().Set("Access-Control-Allow-Origin", "https://allowed.example")
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)
	g.exposeHeaders = true
	g.headers.Set("Content-Type", header.ApplicationGRPC)
	g.headers.Set("Access-Control-Expose-Headers", "X-Service-Header, grpc-status")
	g.headers.Set("Access-Control-Allow-Origin", "https://other.example")
	g.headers.Set("Access-Control-Allow-Credentials", "true")

	g.prepareHeaders()

	parts := strings.Split(resp.Header().Get("Access-Control-Expose-Headers"), ", ")
	counts := make(map[string]int)
	for _, part := range parts {
		counts[strings.ToLower(part)]++
	}
	assert.Equal(t, 1, counts["x-custom-header"])
	assert.Equal(t, 1, counts["x-service-header"])
	assert.Equal(t, 1, counts["grpc-status"])
	assert.Equal(t, 1, counts["grpc-message"])
	assert.Equal(t, 1, counts["content-type"])
	assert.Equal(t, "https://allowed.example", resp.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, resp.Header().Get("Access-Control-Allow-Credentials"))
}

func TestGrpcWebResponse_PreservesCORSVary(t *testing.T) {
	t.Parallel()
	resp := httptest.NewRecorder()
	resp.Header().Add(header.Vary, "Origin")
	resp.Header().Add(header.Vary, "Accept-Encoding")
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)
	g.exposeHeaders = true
	g.headers["vary"] = []string{"Accept-Language, origin"}

	g.prepareHeaders()

	assert.Equal(t, "Origin, Accept-Encoding, Accept-Language", resp.Header().Get(header.Vary))
}

func TestGrpcWebResponse_PreservesCORSVaryFromTrailerMetadata(t *testing.T) {
	t.Parallel()
	resp := httptest.NewRecorder()
	resp.Header().Set(header.Vary, "Origin")
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)
	g.headers[http.TrailerPrefix+header.Vary] = []string{"Accept-Language"}

	g.prepareHeaders()

	assert.Equal(t, "Origin, Accept-Language", resp.Header().Get(header.Vary))
}

func TestGrpcWebResponse_VaryWildcard(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		wrapped  string
		metadata string
	}{
		{name: "wrapped wildcard", wrapped: "*", metadata: "Accept-Language"},
		{name: "metadata wildcard", wrapped: "Origin", metadata: "*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := httptest.NewRecorder()
			resp.Header().Set(header.Vary, tt.wrapped)
			g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)
			g.headers.Set(header.Vary, tt.metadata)

			g.prepareHeaders()

			assert.Equal(t, "*", resp.Header().Get(header.Vary))
		})
	}
}

func TestGrpcWebResponse_NoCORSFromMetadata(t *testing.T) {
	t.Parallel()
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)
	g.headers.Set("Access-Control-Allow-Origin", "*")
	g.headers.Set("Access-Control-Allow-Credentials", "true")
	g.headers.Set("Access-Control-Expose-Headers", "X-Service-Header")
	g.headers[http.TrailerPrefix+"Access-Control-Allow-Origin"] = []string{"*"}
	g.headers[http.TrailerPrefix+"Access-Control-Allow-Credentials"] = []string{"true"}
	g.headers[http.TrailerPrefix+"Access-Control-Expose-Headers"] = []string{"X-Trailer-Header"}

	g.prepareHeaders()

	assert.Empty(t, resp.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, resp.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, resp.Header().Get("Access-Control-Expose-Headers"))
}

func TestGrpcWebResponse_FinishRequest(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)

	g.finishRequest()
	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestExtractTrailingHeaders(t *testing.T) {
	src := http.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer token"},
		"Trailer":       {"grpc-status"},
	}
	flushed := http.Header{
		"Grpc-Status": {"0"},
	}
	headers := (map[string][]string)(extractTrailingHeaders(src, flushed))
	require.Len(t, headers, 2)
	assert.Equal(t, []string{"Bearer token"}, headers["authorization"])
	assert.Equal(t, []string{"application/json"}, headers["content-type"])
}

func TestCopyTrailersToPayload(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)

	g.headers.Set("Grpc-Status", "0")
	g.copyTrailersToPayload()

	trailerData := resp.Body.Bytes()
	require.Greater(t, len(trailerData), 5)
	assert.Equal(t, byte(1<<7), trailerData[0]) // MSB=1 indicates this is a trailer data frame.
}

func TestGrpcWebResponse_WriteText(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText, false)

	data := []byte("test data")
	n, err := g.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	// For text format, response should be base64 encoded
	assert.Equal(t, "dGVzdCBkYXRh", resp.Body.String())
}

func TestGrpcWebResponse_PrepareHeadersText(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText, false)

	g.headers.Set("Content-Type", header.ApplicationGRPCWebText)
	g.exposeHeaders = true
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, header.ApplicationGRPCWebText, h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_CopyTrailersToPayloadText(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText, false)

	g.headers.Set("Grpc-Status", "0")
	g.copyTrailersToPayload()

	// Base64 decoded trailer should start with MSB=1
	trailerData := resp.Body.String()
	decoded, err := base64.StdEncoding.DecodeString(trailerData)
	require.NoError(t, err)
	require.Greater(t, len(decoded), 5)
	assert.Equal(t, byte(1<<7), decoded[0])
}

// TestGrpcWebResponse_NoCompression verifies that when compression is disabled
// (e.g. for streaming calls) the body is written verbatim and no
// Content-Encoding header is set.
func TestGrpcWebResponse_NoCompression(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, false)

	payload := []byte("hello world")
	_, err := g.Write(payload)
	require.NoError(t, err)

	g.finishRequest()

	// No HTTP-level content-encoding must be set.
	assert.Empty(t, resp.Header().Get(header.ContentEncoding))
	// Payload is written verbatim (not gzip compressed).
	assert.True(t, bytes.HasPrefix(resp.Body.Bytes(), payload))
}

func TestGrpcWebResponse_GzipProto(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, true)

	payload := []byte("hello gzip")
	_, err := g.Write(payload)
	require.NoError(t, err)

	g.finishRequest()
	closedLength := resp.Body.Len()
	g.Close()
	assert.Equal(t, closedLength, resp.Body.Len())

	// Content-Encoding header must be set
	assert.Equal(t, header.Gzip, resp.Header().Get(header.ContentEncoding))

	decompressed := mustGunzip(resp.Body.Bytes())
	// The decompressed stream should start with the original payload
	assert.True(t, bytes.HasPrefix(decompressed, payload))
}

func TestGrpcWebResponse_GzipWriteAfterClose(t *testing.T) {
	t.Parallel()
	for _, ct := range []string{header.ApplicationGRPCWebProto, header.ApplicationGRPCWebText} {
		t.Run(ct, func(t *testing.T) {
			t.Parallel()
			resp := httptest.NewRecorder()
			g := newGrpcWebResponse(resp, ct, true)

			_, err := g.Write([]byte("hello gzip"))
			require.NoError(t, err)
			g.finishRequest()
			closed := bytes.Clone(resp.Body.Bytes())

			n, err := g.Write([]byte("late"))
			require.ErrorIs(t, err, errWriteAfterClose)
			assert.Zero(t, n)
			g.finishRequest()
			g.Close()

			assert.Equal(t, closed, resp.Body.Bytes())
			assert.Equal(t, header.Gzip, resp.Header().Get(header.ContentEncoding))
			assert.NotEmpty(t, mustGunzip(resp.Body.Bytes()))
		})
	}
}

func TestGrpcWebResponse_GzipConcurrent(t *testing.T) {
	for range 16 {
		t.Run("response", func(t *testing.T) {
			t.Parallel()
			resp := httptest.NewRecorder()
			g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, true)
			payload := []byte("independent response")
			_, err := g.Write(payload)
			require.NoError(t, err)
			g.finishRequest()
			assert.True(t, bytes.HasPrefix(mustGunzip(resp.Body.Bytes()), payload))
		})
	}
}

func TestGrpcWebResponse_GzipTextStreaming(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText, true)

	// Simulate server-side streaming: write two chunks
	_, err := g.Write([]byte("hello "))
	require.NoError(t, err)
	_, err = g.Write([]byte("world"))
	require.NoError(t, err)

	g.finishRequest()

	decompressed := mustGunzip(resp.Body.Bytes())

	// The decompressed data is a concatenation of independently base64-encoded frames.
	// Instead of decoding the entire stream, we check that it contains the individual
	// base64 representations of our two chunks.
	plain := string(decompressed)
	assert.Contains(t, plain, base64.StdEncoding.EncodeToString([]byte("hello ")))
	assert.Contains(t, plain, base64.StdEncoding.EncodeToString([]byte("world")))
}

// mustGunzip is a helper that decompresses a gzip buffer and panics on error.
func mustGunzip(b []byte) []byte {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		panic(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}
	_ = r.Close()
	return out
}
