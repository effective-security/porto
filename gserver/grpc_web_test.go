package gserver

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"encoding/base64"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrpcWebResponse_Header(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, "")

	headers := g.Header()
	require.NotNil(t, headers)
	assert.Equal(t, 0, len(headers))
}

func TestGrpcWebResponse_Write(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, "")

	data := []byte("test data")
	n, err := g.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, resp.Body.Bytes())
}

func TestGrpcWebResponse_WriteHeader(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, "")

	g.WriteHeader(http.StatusAccepted)
	assert.Equal(t, http.StatusAccepted, resp.Code)
}

func TestGrpcWebResponse_Flush(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, "")

	g.Flush()
	assert.Equal(t, 200, resp.Code)
}

func TestGrpcWebResponse_PrepareHeadersJSON(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, "")

	g.headers.Set("Content-Type", "application/json")
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, "application/json", h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_PrepareHeaders(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, "")

	g.headers.Set("Content-Type", "application/grpc-web+proto")
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, "application/grpc-web+proto", h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_FinishRequest(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, "")

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
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, "")

	g.headers.Set("Grpc-Status", "0")
	g.copyTrailersToPayload()

	trailerData := resp.Body.Bytes()
	require.Greater(t, len(trailerData), 5)
	assert.Equal(t, byte(1<<7), trailerData[0]) // MSB=1 indicates this is a trailer data frame.
}

func TestGrpcWebResponse_WriteText(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText, "")

	data := []byte("test data")
	n, err := g.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	// For text format, response should be base64 encoded
	assert.Equal(t, "dGVzdCBkYXRh", resp.Body.String())
}

func TestGrpcWebResponse_PrepareHeadersText(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText, "")

	g.headers.Set("Content-Type", header.ApplicationGRPCWebText)
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, header.ApplicationGRPCWebText, h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_CopyTrailersToPayloadText(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText, "")

	g.headers.Set("Grpc-Status", "0")
	g.copyTrailersToPayload()

	// Base64 decoded trailer should start with MSB=1
	trailerData := resp.Body.String()
	decoded, err := base64.StdEncoding.DecodeString(trailerData)
	require.NoError(t, err)
	require.Greater(t, len(decoded), 5)
	assert.Equal(t, byte(1<<7), decoded[0])
}

func TestGrpcWebResponse_GzipProto(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto, header.Gzip)

	payload := []byte("hello gzip")
	_, err := g.Write(payload)
	require.NoError(t, err)

	g.finishRequest()

	// Content-Encoding header must be set
	assert.Equal(t, header.Gzip, resp.Header().Get(header.ContentEncoding))

	decompressed := mustGunzip(resp.Body.Bytes())
	// The decompressed stream should start with the original payload
	assert.True(t, bytes.HasPrefix(decompressed, payload))
}

func TestGrpcWebResponse_GzipTextStreaming(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText, header.Gzip)

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
