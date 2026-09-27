package correlation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestCorrelationID(t *testing.T) {
	v := Value(context.Background())
	assert.Nil(t, v)
	v = Value(WithID(NewFromContext(context.Background())))
	assert.NotNil(t, v)

	d := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := ID(r.Context())
		assert.NotEmpty(t, cid)
	})
	rw := httptest.NewRecorder()
	handler := NewHandler(d)
	r, err := http.NewRequest("GET", "/test", nil)
	require.NoError(t, err)
	r.RemoteAddr = "10.0.0.1"
	r.Header.Add(header.XCorrelationID, "1234567890")

	handler.ServeHTTP(rw, r)
	assert.NotEmpty(t, rw.Header().Get(header.XCorrelationID))

	ctx := WithID(r.Context())
	assert.NotEmpty(t, ID(ctx))
	assert.NotEmpty(t, ID(WithMetaFromRequest(r)))

	ctx2 := WithMetaFromContext(context.Background())
	cid := ID(ctx2)
	assert.NotEmpty(t, ID(ctx2))

	md, ok := metadata.FromOutgoingContext(ctx2)
	require.True(t, ok)
	assert.Equal(t, cid, md[CorrelationIDgRPCHeaderName][0])
}

func TestWithMetaFromRequestCorrelationID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		headerName          string
		headerID            string
		correlationHeaderID string
		wantID              string
	}{
		{name: "generated"},
		{
			name:       "request ID",
			headerName: "X-Request-ID",
			headerID:   "request-id",
			wantID:     "request-id",
		},
		{
			name:       "long request ID",
			headerName: "X-Request-ID",
			headerID:   "123456789012345",
			wantID:     "123456789012",
		},
		{
			name:                "conflicting IDs",
			headerName:          "X-Request-ID",
			headerID:            "other-request-id",
			correlationHeaderID: "selected-id",
			wantID:              "selected-id",
		},
		{
			name:       "long correlation ID",
			headerName: header.XCorrelationID,
			headerID:   "123456789012345",
			wantID:     "123456789012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.headerName != "" {
				req.Header.Set(tt.headerName, tt.headerID)
			}
			if tt.correlationHeaderID != "" {
				req.Header.Set(header.XCorrelationID, tt.correlationHeaderID)
			}
			ctx := WithMetaFromRequest(req)
			cid := ID(ctx)
			if tt.wantID == "" {
				require.Len(t, cid, IDSize)
			} else {
				require.Equal(t, tt.wantID, cid)
			}

			incoming, ok := metadata.FromIncomingContext(ctx)
			require.True(t, ok)
			assert.Equal(t, []string{cid}, incoming.Get(CorrelationIDgRPCHeaderName))
			assert.NotContains(t, incoming, header.XCorrelationID)

			outgoing, ok := metadata.FromOutgoingContext(ctx)
			require.True(t, ok)
			assert.Equal(t, []string{cid}, outgoing.Get(CorrelationIDgRPCHeaderName))

			if tt.headerName == "X-Request-ID" {
				assert.Equal(t, []string{cid}, incoming.Get(requestIDgRPCHeaderName))
				assert.Equal(t, []string{cid}, outgoing.Get(requestIDgRPCHeaderName))
			} else {
				assert.NotContains(t, incoming, requestIDgRPCHeaderName)
				assert.NotContains(t, outgoing, requestIDgRPCHeaderName)
			}
		})
	}
}

func Test_grpcFromContext(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		unary := NewAuthUnaryInterceptor()
		var cid1 string
		var rctx context.Context
		_, _ = unary(context.Background(), nil, nil, func(ctx context.Context, req any) (any, error) {
			cid1 = ID(ctx)
			assert.NotEmpty(t, cid1)
			rctx = ctx
			return nil, nil
		})
		cid2 := ID(rctx)
		assert.Equal(t, cid1, cid2)

		octx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(header.XCorrelationID, "1234567890"))
		_, _ = unary(octx, nil, nil, func(ctx context.Context, req any) (any, error) {
			cid1 = ID(ctx)
			assert.Contains(t, cid1, "1234567890")
			rctx = ctx
			return nil, nil
		})
	})
}

func TestCorrelationIDHandler(t *testing.T) {
	d := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := ID(r.Context())
		w.Header().Set(header.XCorrelationID, cid)
	})

	t.Run("no_from_client", func(t *testing.T) {
		rw := httptest.NewRecorder()
		handler := NewHandler(d)
		r, _ := http.NewRequest("GET", "/test", nil)

		handler.ServeHTTP(rw, r)
		cid := rw.Header().Get(header.XCorrelationID)
		assert.Len(t, cid, IDSize)
	})

	t.Run("show_from_client", func(t *testing.T) {
		rw := httptest.NewRecorder()
		handler := NewHandler(d)
		r, _ := http.NewRequest("GET", "/test", nil)
		r.Header.Set(header.XCorrelationID, "1234") // short incoming

		handler.ServeHTTP(rw, r)
		cid := rw.Header().Get(header.XCorrelationID)
		assert.Equal(t, "1234", cid)
	})

	t.Run("long_from_client", func(t *testing.T) {
		rw := httptest.NewRecorder()
		handler := NewHandler(d)
		r, _ := http.NewRequest("GET", "/test", nil)
		r.Header.Set(header.XCorrelationID, "1234jsehdrlcfkjwhelckjqhewlkcjhqwlekcjhqeq")

		handler.ServeHTTP(rw, r)
		cid := rw.Header().Get(header.XCorrelationID)
		assert.Equal(t, "1234jsehdrlc", cid)
	})
}
