package gserver

import (
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func TestLogInterceptorsCountEscapingPanics(t *testing.T) {
	// The sink is process-global; these tests must run serially.
	for _, stream := range []bool{false, true} {
		counts := newMetricsSink(t)
		const method = "/test.Service/Panic"
		s := &Server{cfg: Config{SkipLogPaths: []telemetry.LoggerSkipPath{{Path: method, Agent: "*"}}}}
		ctx := context.Background()
		assert.PanicsWithValue(t, "boom", func() {
			if stream {
				err := s.newLogStreamServerInterceptor()(nil, &ctxServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: method}, func(any, grpc.ServerStream) error {
					panic("boom")
				})
				assert.NoError(t, err)
			} else {
				_, err := s.newLogUnaryInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) {
					panic("boom")
				})
				assert.NoError(t, err)
			}
		})
		assert.Equal(t, map[string]int{
			metricsTestPrefix + "_rpc_requests_perf;api=" + method + ";status=Internal":            1,
			metricsTestPrefix + "_rpc_requests_role;api=" + method + ";status=Internal;role=guest": 1,
		}, counts())
	}
}

func TestLogRequestWrappedErrors(t *testing.T) {
	counts := newMetricsSink(t)
	s := &Server{}
	want := map[string]int{}
	for _, tc := range []struct {
		err  error
		code codes.Code
	}{
		{errors.New("backend failed"), codes.Unknown},
		{errors.WithStack(httperror.InvalidRequest("bad value")), codes.InvalidArgument},
		{errors.WithStack(httperror.NewMany(http.StatusConflict, httperror.CodeConflict, "conflict")), codes.AlreadyExists},
	} {
		_, err := s.newLogUnaryInterceptor()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Error"}, func(context.Context, any) (any, error) {
			return nil, tc.err
		})
		assert.ErrorIs(t, err, tc.err)
		maps.Copy(want, map[string]int{
			metricsTestPrefix + "_rpc_requests_perf;api=/test/Error;status=" + tc.code.String():                 1,
			metricsTestPrefix + "_rpc_requests_role;api=/test/Error;status=" + tc.code.String() + ";role=guest": 1,
		})
	}
	assert.Equal(t, want, counts())
}

func TestHTTPPanicRecovery(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		write func(http.ResponseWriter)
		panic any
		abort bool
	}{
		{name: "before response", panic: "boom"},
		{name: "informational", write: func(w http.ResponseWriter) { w.WriteHeader(http.StatusEarlyHints) }, panic: "boom"},
		{name: "status", write: func(w http.ResponseWriter) { w.WriteHeader(http.StatusAccepted) }, panic: "boom", abort: true},
		{name: "body", write: func(w http.ResponseWriter) { _, _ = io.WriteString(w, "partial") }, panic: "boom", abort: true},
		{name: "flush", write: func(w http.ResponseWriter) { w.(http.Flusher).Flush() }, panic: "boom", abort: true},
		{name: "abort", panic: http.ErrAbortHandler, abort: true},
		{name: "wrapped abort", panic: errors.WithStack(http.ErrAbortHandler), abort: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sctx := &serveCtx{cfg: &Config{}}
			h := sctx.grpcHandlerFunc(grpc.NewServer(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.write != nil {
					tc.write(w)
				}
				panic(tc.panic)
			}))
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.abort {
				assert.PanicsWithValue(t, http.ErrAbortHandler, func() { h.ServeHTTP(w, r) })
				assert.NotContains(t, w.Body.String(), unhandledException)
			} else {
				assert.NotPanics(t, func() { h.ServeHTTP(w, r) })
				assert.Equal(t, unhandledException+"\n", w.Body.String())
			}
		})
	}
}

func TestTLSPanicAbortsPartialResponse(t *testing.T) {
	t.Parallel()
	sctx := &serveCtx{cfg: &Config{}}
	h := sctx.grpcHandlerFunc(grpc.NewServer(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		panic("boom")
	}))
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Timeout = lifecycleWait
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Equal(t, "partial", string(body))
}
