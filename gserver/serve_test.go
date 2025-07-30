package gserver

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestGrpcHandlerFunc(t *testing.T) {
	grpcServer := grpc.NewServer()
	otherHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("other handler"))
	})

	sctx := &serveCtx{
		cfg: &Config{
			CORS: &CORS{
				AllowedOrigins: []string{"http://example.com"},
				ExposedHeaders: []string{"X-Custom-Header"},
			},
		},
	}

	handler := sctx.grpcHandlerFunc(grpcServer, otherHandler)

	t.Run("gRPC_request_http1", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(header.ContentType, header.ApplicationGRPC)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusHTTPVersionNotSupported, w.Code)
	})

	t.Run("gRPC_request_http2", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(header.ContentType, header.ApplicationGRPC)
		req.Header.Set("Origin", "http://example.com")
		req.Proto = "HTTP/2"
		req.ProtoMajor = 2
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		hd := w.Header()
		assert.Equal(t, "application/grpc", hd.Get("Content-Type"))
		assert.Equal(t, "12", hd.Get("Grpc-Status"))
		assert.Equal(t, "malformed method name: \"/\"", hd.Get("Grpc-Message"))
	})

	t.Run("gRPC-Web request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(header.ContentType, header.ApplicationGRPCWebProto)
		req.Header.Set("Origin", "http://example.com")
		req.Proto = "HTTP/2"
		req.ProtoMajor = 2

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		hd := w.Header()
		assert.Equal(t, "http://example.com", hd.Get("Access-Control-Allow-Origin"))
		vals := strings.Split(hd.Get("Access-Control-Expose-Headers"), ", ")
		sort.Strings(vals)
		assert.Equal(t, []string{"Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Content-Type", "Date", "Grpc-Message", "Grpc-Status", "grpc-message", "grpc-status"}, vals)
	})

	t.Run("gRPC-Web-Text request", func(t *testing.T) {
		payload := base64.StdEncoding.EncodeToString([]byte("test-payload"))
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
		req.Header.Set(header.ContentType, header.ApplicationGRPCWebText)
		req.Header.Set("Origin", "http://example.com")
		req.Proto = "HTTP/2"
		req.ProtoMajor = 2

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		hd := w.Header()
		assert.Equal(t, "http://example.com", hd.Get("Access-Control-Allow-Origin"))
		vals := strings.Split(hd.Get("Access-Control-Expose-Headers"), ", ")
		sort.Strings(vals)
		assert.Equal(t, []string{"Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Content-Type", "Date", "Grpc-Message", "Grpc-Status", "grpc-message", "grpc-status"}, vals)
	})

	t.Run("Other request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "other handler", w.Body.String())
	})

	t.Run("CORS not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(header.ContentType, header.ApplicationGRPCWebProto)
		req.Header.Set("Origin", "http://notallowed.com")
		req.Proto = "HTTP/2"
		req.ProtoMajor = 2

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("Debug logs", func(t *testing.T) {
		sctx.cfg.DebugLogs = true
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("test"))
		req.Header.Set(header.ContentType, header.ApplicationGRPC)
		req.Proto = "HTTP/2"
		req.ProtoMajor = 2

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("gRPC-Web failure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(header.ContentType, header.ApplicationGRPCWebProto)
		req.Header.Set(header.AcceptEncoding, header.Gzip)
		req.Header.Set("Origin", "http://example.com")
		req.Proto = "HTTP/2"
		req.ProtoMajor = 2

		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		hd := w.Header()
		// content-type should be sent even if there is an error
		assert.Equal(t, header.ApplicationGRPCWebProto, hd.Get("Content-Type"))
		assert.Equal(t, "12", hd.Get("Grpc-Status"))
		assert.Equal(t, "malformed method name: \"/\"", hd.Get("Grpc-Message"))
	})
}
