package gserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrpcWebResponse_Header(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp)

	headers := g.Header()
	require.NotNil(t, headers)
	assert.Equal(t, 0, len(headers))
}

func TestGrpcWebResponse_Write(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp)

	data := []byte("test data")
	n, err := g.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, resp.Body.Bytes())
}

func TestGrpcWebResponse_WriteHeader(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp)

	g.WriteHeader(http.StatusAccepted)
	assert.Equal(t, http.StatusAccepted, resp.Code)
}

func TestGrpcWebResponse_Flush(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp)

	g.Flush()
	assert.Equal(t, 200, resp.Code)
}

func TestGrpcWebResponse_PrepareHeadersJSON(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp)

	g.headers.Set("Content-Type", "application/json")
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, "application/json", h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_PrepareHeaders(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp)

	g.headers.Set("Content-Type", "application/grpc-web+proto")
	g.prepareHeaders()

	h := resp.Header()
	assert.Equal(t, "application/grpc-web+proto", h.Get("Content-Type"))
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-status")
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "grpc-message")
}

func TestGrpcWebResponse_FinishRequest(t *testing.T) {
	resp := httptest.NewRecorder()
	g := newGrpcWebResponse(resp)

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
	g := newGrpcWebResponse(resp)

	g.headers.Set("Grpc-Status", "0")
	g.copyTrailersToPayload()

	trailerData := resp.Body.Bytes()
	require.Greater(t, len(trailerData), 5)
	assert.Equal(t, byte(1<<7), trailerData[0]) // MSB=1 indicates this is a trailer data frame.
}
