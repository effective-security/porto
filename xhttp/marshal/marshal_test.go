package marshal

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errWithStack = errors.Errorf("important info")

func TestWritePlainJSON(t *testing.T) {
	v := &AStruct{
		A: "a",
		B: "b",
	}

	t.Run("DontPrettyPrint", func(t *testing.T) {
		w := httptest.NewRecorder()
		WritePlainJSON(w, http.StatusOK, v, DontPrettyPrint)
		assert.Equal(t, `{"A":"a","B":"b"}`, w.Body.String())
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
	})

	t.Run("PrettyPrint", func(t *testing.T) {
		pretty := `{
	"A": "a",
	"B": "b"
}`
		w := httptest.NewRecorder()
		WritePlainJSON(w, http.StatusCreated, v, PrettyPrint)
		assert.Equal(t, pretty, w.Body.String())
		assert.Equal(t, http.StatusCreated, w.Code)
		assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
	})
}

func TestWriteJSON(t *testing.T) {
	v := &AStruct{
		A: "a",
		B: "b",
	}
	r, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	WriteJSON(w, r, v)
	assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
	assert.Equal(t, `{"A":"a","B":"b"}`, w.Body.String())
	assert.Empty(t, w.Header().Get(header.ContentEncoding))
	assert.Equal(t, header.AcceptEncoding, w.Header().Get(header.Vary))
}

func TestWriteJSONCompression(t *testing.T) {
	const jsonOverhead = len(`{"Data":""}`)
	tcases := []struct {
		name     string
		accept   string
		size     int
		wantGzip bool
	}{
		{name: "small gzip", accept: "gzip", size: minGzipSize - 1},
		{name: "threshold gzip", accept: "gzip", size: minGzipSize, wantGzip: true},
		{name: "large no accept", size: minGzipSize + 1},
		{name: "gzip disabled", accept: "gzip;q=0", size: minGzipSize + 1},
		{name: "gzip quality", accept: "br, gzip;q=0.5", size: minGzipSize + 1, wantGzip: true},
		{name: "gzip case", accept: "GZIP;Q=0.5", size: minGzipSize + 1, wantGzip: true},
		{name: "wildcard", accept: "*;q=0.5", size: minGzipSize + 1, wantGzip: true},
		{name: "explicit denial", accept: "gzip;q=0, *;q=1", size: minGzipSize + 1},
		{name: "substring", accept: "xgzip", size: minGzipSize + 1},
		{name: "invalid quality", accept: "gzip;q=bogus", size: minGzipSize + 1},
		{name: "out of range quality", accept: "gzip;q=2", size: minGzipSize + 1},
		{name: "empty quality", accept: "gzip;q", size: minGzipSize + 1},
		{name: "non-quality parameter", accept: "gzip;level=1", size: minGzipSize + 1, wantGzip: true},
		{name: "trailing semicolon", accept: "gzip;", size: minGzipSize + 1, wantGzip: true},
		{name: "quality after parameter", accept: "gzip;level=1;q=0", size: minGzipSize + 1},
		{name: "wildcard parameter", accept: "*;level=1", size: minGzipSize + 1, wantGzip: true},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			payload := struct{ Data string }{Data: strings.Repeat("x", tc.size-jsonOverhead)}
			plain, err := EncodeBytes(DontPrettyPrint, payload)
			require.NoError(t, err)
			require.Len(t, plain, tc.size)

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set(header.AcceptEncoding, tc.accept)
			w := httptest.NewRecorder()
			w.Header().Set(header.Vary, "Origin")
			WriteJSON(w, r, payload)
			assert.Equal(t, []string{"Origin", header.AcceptEncoding}, w.Header().Values(header.Vary))
			assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
			assert.Equal(t, http.StatusOK, w.Code)

			actual := w.Body.Bytes()
			if tc.wantGzip {
				assert.Equal(t, header.Gzip, w.Header().Get(header.ContentEncoding))
				gz, err := gzip.NewReader(bytes.NewReader(actual))
				require.NoError(t, err)
				actual, err = io.ReadAll(gz)
				require.NoError(t, err)
				require.NoError(t, gz.Close())
			} else {
				assert.Empty(t, w.Header().Get(header.ContentEncoding))
			}
			assert.Equal(t, plain, actual)
		})
	}
}

func TestWriteJSONVaryExisting(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	w.Header().Set(header.Vary, "Origin, accept-encoding")
	WriteJSON(w, r, struct{}{})
	assert.Equal(t, []string{"Origin, accept-encoding"}, w.Header().Values(header.Vary))
}

func TestWriteJSON_Error(t *testing.T) {
	withRequestID := httperror.Unexpected("db down")
	withRequestID.RequestID = "req-1"
	statusWithRequestID := status.ErrorProto(withRequestID.GRPCStatus().Proto())

	tcases := []struct {
		err error
		exp string
		log string
	}{
		{
			httperror.NotFound("foo"),
			`{"code":"not_found","message":"foo"}`,
			"",
		},
		{
			httperror.NotFound("foo").WithCause(errWithStack),
			`{"code":"not_found","message":"foo"}`,
			"",
		},
		{
			httperror.InvalidParam("foo"),
			`{"code":"invalid_parameter","message":"foo"}`,
			"I | pkg=xhttp, type=API_ERROR, path=\"/test\", status=400, code=invalid_parameter, msg=foo, content-length=0, fn=marshal_test.go, ln=%d\n",
		},
		{
			httperror.InvalidParam("foo").WithCause(errWithStack),
			`{"code":"invalid_parameter","message":"foo"}`,
			"I | pkg=xhttp, type=API_ERROR, path=\"/test\", status=400, code=invalid_parameter, msg=foo, content-length=0, fn=marshal_test.go, ln=%d, err=\"important info\"\n",
		},
		{
			httperror.Unexpected("bar"), //.WithCause(errWithStack),
			`{"code":"unexpected","message":"bar"}`,
			"E | pkg=xhttp, type=INTERNAL_ERROR, path=\"/test\", status=500, code=unexpected, msg=bar, content-length=0, fn=marshal_test.go, ln=%d\n",
		},
		{
			// A plain error is a server-side failure: the client gets the
			// generic status text, the log keeps the error and the caller's line.
			errors.Errorf("generic"),
			`{"code":"unexpected","message":"Internal Server Error"}`,
			"E | pkg=xhttp, type=INTERNAL_ERROR, path=\"/test\", status=500, code=unexpected, msg=\"Internal Server Error\", content-length=0, fn=marshal_test.go, ln=%d, err=\"generic",
		},
		{
			status.Error(codes.Internal, "db down"),
			`{"code":"unexpected","message":"Internal Server Error"}`,
			"E | pkg=xhttp, type=INTERNAL_ERROR, path=\"/test\", status=500, code=unexpected, msg=\"Internal Server Error\", content-length=0, fn=marshal_test.go, ln=%d, err=\"rpc error: code = Internal desc = db down\"",
		},
		{
			// The correlation ID carried by a status detail survives the generic message.
			statusWithRequestID,
			`{"code":"unexpected","request_id":"req-1","message":"Internal Server Error"}`,
			"E | pkg=xhttp, type=INTERNAL_ERROR, path=\"/test\", status=500, code=unexpected, msg=\"Internal Server Error\", content-length=0, fn=marshal_test.go, ln=%d, err=\"rpc error: code = Internal desc = db down\"",
		},
		{
			status.Error(codes.Unavailable, "upstream down"),
			`{"code":"unavailable","message":"Service Unavailable"}`,
			"E | pkg=xhttp, type=INTERNAL_ERROR, path=\"/test\", status=503, code=unavailable, msg=\"Service Unavailable\", content-length=0, fn=marshal_test.go, ln=%d, err=\"rpc error: code = Unavailable desc = upstream down\"",
		},
		{
			// Client errors keep their message.
			status.Error(codes.PermissionDenied, "not for you"),
			`{"code":"forbidden","message":"not for you"}`,
			"I | pkg=xhttp, type=API_ERROR, path=\"/test\", status=403, code=forbidden, msg=\"not for you\", content-length=0, fn=marshal_test.go, ln=%d\n",
		},
		{
			status.Error(codes.NotFound, "no such thing"),
			`{"code":"not_found","message":"no such thing"}`,
			"",
		},
		{
			errors.WithMessage(httperror.InvalidParam("bar"), "wrapped"),
			`{"code":"invalid_parameter","message":"bar"}`,
			"I | pkg=xhttp, type=API_ERROR, path=\"/test\", status=400, code=invalid_parameter, msg=bar, content-length=0, fn=marshal_test.go, ln=%d\n",
		},
		{
			httperror.NewGrpcFromCtx(context.Background(), codes.InvalidArgument, "pberror1"),
			`{"code":"bad_request","message":"pberror1"}`,
			"I | pkg=xhttp, type=API_ERROR, path=\"/test\", status=400, code=bad_request, msg=pberror1, content-length=0, fn=marshal_test.go, ln=%d\n",
		},
		{
			errors.WithMessage(httperror.NewGrpcFromCtx(context.Background(), codes.InvalidArgument, "pberror2"), "wrapped"),
			`{"code":"bad_request","message":"pberror2"}`,
			"I | pkg=xhttp, type=API_ERROR, path=\"/test\", status=400, code=bad_request, msg=pberror2, content-length=0, fn=marshal_test.go, ln=%d\n",
		},
		{
			errors.WithMessage(httperror.NewGrpcFromCtx(context.Background(), codes.InvalidArgument, "pberror2").WithCause(errWithStack), "wrapped"),
			`{"code":"bad_request","message":"pberror2"}`,
			"I | pkg=xhttp, type=API_ERROR, path=\"/test\", status=400, code=bad_request, msg=pberror2, content-length=0, fn=marshal_test.go, ln=%d, err=\"important info\"\n",
		},
	}

	for i, tc := range tcases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			var b bytes.Buffer
			writer := bufio.NewWriter(&b)

			xlog.SetGlobalLogLevel(xlog.INFO)
			xlog.SetFormatter(xlog.NewPrettyFormatter(writer).Options(xlog.FormatSkipTime(true), xlog.FormatWithCaller(false)))

			r, _ := http.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			_, _, callerLine, _ := runtime.Caller(0)
			WriteJSON(w, r, tc.err) // must stay on the line right after runtime.Caller
			assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
			assert.Equal(t, tc.exp, w.Body.String())

			expLog := tc.log
			if strings.Contains(expLog, "ln=%d") {
				expLog = fmt.Sprintf(expLog, callerLine+1)
			}
			if !assert.Contains(t, b.String(), expLog) {
				t.Log(b.String())
				t.Log(expLog)
			}
		})
	}
}

func TestNewRequest(t *testing.T) {
	m := map[string]string{
		"key": "value",
	}
	tcases := []struct {
		req any
		exp string
	}{
		{m, `{"key":"value"}`},
		{"string", `string`},
		{[]byte(`bytes`), `bytes`},
		{bytes.NewReader([]byte(`bytes`)), `bytes`},
		{strings.NewReader(`string`), `string`},
	}

	for _, tc := range tcases {
		t.Run(reflect.TypeOf(tc.req).Name(), func(t *testing.T) {
			r, err := NewRequest(http.MethodGet, "/test", tc.req)
			require.NoError(t, err)
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Equal(t, tc.exp, string(body))
		})
	}
}
