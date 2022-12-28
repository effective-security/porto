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

func Test_grpcFromContext(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		unary := NewAuthUnaryInterceptor()
		var cid1 string
		var rctx context.Context
		_, _ = unary(context.Background(), nil, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
			cid1 = ID(ctx)
			assert.NotEmpty(t, cid1)
			rctx = ctx
			return nil, nil
		})
		cid2 := ID(rctx)
		assert.Equal(t, cid1, cid2)

		octx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(header.XCorrelationID, "1234567890"))
		_, _ = unary(octx, nil, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
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
