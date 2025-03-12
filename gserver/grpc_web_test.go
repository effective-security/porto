package gserver

import (
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
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto)

	headers := g.Header()
	require.NotNil(t, headers)
	assert.Equal(t, 0, len(headers))
}

func TestGrpcWebResponse_Write(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto)

	data := []byte("test data")
	n, err := g.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, resp.Body.Bytes())
}

func TestGrpcWebResponse_WriteHeader(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto)

	g.WriteHeader(http.StatusAccepted)
	assert.Equal(t, http.StatusAccepted, resp.Code)
}

func TestGrpcWebResponse_Flush(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto)

	g.Flush()
	assert.Equal(t, 200, resp.Code)
}

func TestGrpcWebResponse_PrepareHeadersJSON(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto)

	g.headers.Set("Content-Type", "application/json")
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, "application/json", h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_PrepareHeaders(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto)

	g.headers.Set("Content-Type", "application/grpc-web+proto")
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, "application/grpc-web+proto", h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_FinishRequest(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto)

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
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebProto)

	g.headers.Set("Grpc-Status", "0")
	g.copyTrailersToPayload()

	trailerData := resp.Body.Bytes()
	require.Greater(t, len(trailerData), 5)
	assert.Equal(t, byte(1<<7), trailerData[0]) // MSB=1 indicates this is a trailer data frame.
}

func TestGrpcWebResponse_WriteText(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText)

	data := []byte("test data")
	n, err := g.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	// For text format, response should be base64 encoded
	assert.Equal(t, "dGVzdCBkYXRh", resp.Body.String())
}

func TestGrpcWebResponse_PrepareHeadersText(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText)

	g.headers.Set("Content-Type", header.ApplicationGRPCWebText)
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, header.ApplicationGRPCWebText, h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_CopyTrailersToPayloadText(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp, header.ApplicationGRPCWebText)

	g.headers.Set("Grpc-Status", "0")
	g.copyTrailersToPayload()

	// Base64 decoded trailer should start with MSB=1
	trailerData := resp.Body.String()
	decoded, err := base64.StdEncoding.DecodeString(trailerData)
	require.NoError(t, err)
	require.Greater(t, len(decoded), 5)
	assert.Equal(t, byte(1<<7), decoded[0])
}
