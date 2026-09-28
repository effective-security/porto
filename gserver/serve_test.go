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
	enabled := true
	grpcServer := grpc.NewServer()
	otherHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("other handler"))
	})

	sctx := &serveCtx{
		cfg: &Config{
			CORS: &CORS{
				Enabled:        &enabled,
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
		assert.Equal(t, []string{"Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Content-Type", "Date", "Grpc-Message", "Grpc-Status", "Vary", "X-Custom-Header"}, vals)
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
		assert.Equal(t, []string{"Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Content-Type", "Date", "Grpc-Message", "Grpc-Status", "Vary", "X-Custom-Header"}, vals)
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

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, w.Header().Get("Access-Control-Expose-Headers"))
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
		assert.Contains(t, w.Header().Values("Vary"), "Origin")
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

func TestGrpcHandlerFuncCORS(t *testing.T) {
	t.Parallel()
	enabled := true
	disabled := false
	tests := []struct {
		name       string
		cors       *CORS
		origin     string
		wantStatus int
		wantOrigin string
		wantExpose bool
		wantCreds  string
	}{
		{
			name:       "absent configuration",
			origin:     "https://example.com",
			wantStatus: http.StatusOK,
		},
		{
			name: "disabled configuration",
			cors: &CORS{
				Enabled:        &disabled,
				AllowedOrigins: []string{"*"},
				ExposedHeaders: []string{"X-Custom-Header"},
			},
			origin:     "https://example.com",
			wantStatus: http.StatusOK,
		},
		{
			name:       "enabled with no origins",
			cors:       &CORS{Enabled: &enabled},
			origin:     "https://example.com",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "enabled with no origin header",
			cors:       &CORS{Enabled: &enabled},
			wantStatus: http.StatusOK,
		},
		{
			name: "explicit wildcard",
			cors: &CORS{
				Enabled:        &enabled,
				AllowedOrigins: []string{"*"},
			},
			origin:     "https://example.com",
			wantStatus: http.StatusOK,
			wantOrigin: "*",
			wantExpose: true,
		},
		{
			name: "explicit origin with credentials",
			cors: &CORS{
				Enabled:          &enabled,
				AllowedOrigins:   []string{"https://example.com"},
				AllowCredentials: &enabled,
			},
			origin:     "https://example.com",
			wantStatus: http.StatusOK,
			wantOrigin: "https://example.com",
			wantExpose: true,
			wantCreds:  "true",
		},
		{
			name: "exact match",
			cors: &CORS{
				Enabled:        &enabled,
				AllowedOrigins: []string{"https://example.com"},
			},
			origin:     "https://example.com",
			wantStatus: http.StatusOK,
			wantOrigin: "https://example.com",
			wantExpose: true,
		},
		{
			name: "configured origin pattern",
			cors: &CORS{
				Enabled:        &enabled,
				AllowedOrigins: []string{"https://*.example.com"},
			},
			origin:     "https://tenant.example.com",
			wantStatus: http.StatusOK,
			wantOrigin: "https://tenant.example.com",
			wantExpose: true,
		},
		{
			name: "explicit list rejects another origin",
			cors: &CORS{
				Enabled:        &enabled,
				AllowedOrigins: []string{"https://allowed.example"},
			},
			origin:     "https://example.com",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sctx := &serveCtx{cfg: &Config{CORS: tt.cors}}
			var other http.Handler = http.NotFoundHandler()
			if tt.cors.GetEnabled() {
				other = corsHandler(tt.cors, other)
			}
			handler := sctx.grpcHandlerFunc(grpc.NewServer(), other)
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set(header.ContentType, header.ApplicationGRPCWebProto)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.wantOrigin, w.Header().Get("Access-Control-Allow-Origin"))
			assert.Equal(t, tt.wantCreds, w.Header().Get("Access-Control-Allow-Credentials"))
			assert.Equal(t, tt.wantExpose, w.Header().Get("Access-Control-Expose-Headers") != "")

			if tt.origin != "" {
				preflight := httptest.NewRequest(http.MethodOptions, "/", nil)
				preflight.Header.Set("Origin", tt.origin)
				preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
				preflight.Header.Set("Access-Control-Request-Headers", "content-type")
				preflightResponse := httptest.NewRecorder()
				handler.ServeHTTP(preflightResponse, preflight)

				assert.Equal(t, tt.wantOrigin, preflightResponse.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, tt.wantCreds, preflightResponse.Header().Get("Access-Control-Allow-Credentials"))
			}
		})
	}
}
