package marshal

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
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

	r.Header.Set(header.AcceptEncoding, header.Gzip)
	w = httptest.NewRecorder()
	WriteJSON(w, r, v)
	assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
	assert.Equal(t, header.Gzip, w.Header().Get(header.ContentEncoding))
	assert.Equal(t, "\x1f\x8b\b\x00\x00\x00\x00\x00\x00\xff\xaaVrT\xb2RJT\xd2QrR\xb2RJR\xaa\x05\x04\x00\x00\xff\xff\xddz\x03\xa1\x11\x00\x00\x00", w.Body.String())
}

func TestWriteJSON_Error(t *testing.T) {
	tcases := []struct {
		err error
		exp string
		log string
	}{
		{
			httperror.NotFound("foo"),
			`{"code":"not_found","message":"foo"}`,
			"W | pkg=xhttp, type=\"API_ERROR\", path=\"/test\", status=404, code=\"not_found\", msg=\"foo\", content-length=0, fn=\"marshal_test.go\", ln=130\n",
		},
		{
			httperror.NotFound("foo").WithCause(errWithStack),
			`{"code":"not_found","message":"foo"}`,
			"W | pkg=xhttp, err=\"important info\"\nW | pkg=xhttp, type=\"API_ERROR\", path=\"/test\", status=404, code=\"not_found\", msg=\"foo\", content-length=0, fn=\"marshal_test.go\", ln=130\n",
		},
		{
			httperror.Unexpected("bar"), //.WithCause(errWithStack),
			`{"code":"unexpected","message":"bar"}`,
			"E | pkg=xhttp, type=\"INTERNAL_ERROR\", path=\"/test\", status=500, code=\"unexpected\", msg=\"bar\", content-length=0, fn=\"marshal_test.go\", ln=130\n",
		},
		// {
		// 	errors.Errorf("generic"),
		// 	`{"code":"unexpected","message":"generic"}`,
		// 	"E | pkg=xhttp, err=\"generic\\ngithub.com/effective-security/porto/xhttp/marshal.TestWriteJSON_Error\\n\\t/home/dissoupov/code/es/porto/xhttp/marshal/marshal_test.go:94\\ntesting.tRunner\\n\\t/usr/local/go/src/testing/testing.go:1576\\nruntime.goexit\\n\\t/usr/local/go/src/runtime/asm_amd64.s:1598\"\nE | pkg=xhttp, type=\"INTERNAL_ERROR\", path=\"/test\", status=500, code=\"unexpected\", msg=\"generic\", content-length=0, fn=\"marshal.go\", ln=73\n",
		// },
		{
			fmt.Errorf("fmt"),
			`{"code":"unexpected","message":"fmt"}`,
			"E | pkg=xhttp, err=\"fmt\"\nE | pkg=xhttp, type=\"INTERNAL_ERROR\", path=\"/test\", status=500, code=\"unexpected\", msg=\"fmt\", content-length=0, fn=\"marshal.go\", ln=73\n",
		},
		{
			errors.WithMessage(httperror.InvalidParam("bar"), "wrapped"),
			`{"code":"invalid_parameter","message":"bar"}`,
			"W | pkg=xhttp, type=\"API_ERROR\", path=\"/test\", status=400, code=\"invalid_parameter\", msg=\"bar\", content-length=0, fn=\"marshal_test.go\", ln=130\n",
		},
		{
			httperror.NewGrpcFromCtx(context.Background(), codes.InvalidArgument, "pberror1"),
			`{"code":"bad_request","message":"pberror1"}`,
			"W | pkg=xhttp, type=\"API_ERROR\", path=\"/test\", status=400, code=\"bad_request\", msg=\"pberror1\", content-length=0, fn=\"marshal_test.go\", ln=130\n",
		},
		{
			errors.WithMessage(httperror.NewGrpcFromCtx(context.Background(), codes.InvalidArgument, "pberror2"), "wrapped"),
			`{"code":"bad_request","message":"pberror2"}`,
			"W | pkg=xhttp, type=\"API_ERROR\", path=\"/test\", status=400, code=\"bad_request\", msg=\"pberror2\", content-length=0, fn=\"marshal_test.go\", ln=130\n",
		},
	}

	for i, tc := range tcases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			var b bytes.Buffer
			writer := bufio.NewWriter(&b)

			xlog.SetGlobalLogLevel(xlog.INFO)
			xlog.SetFormatter(xlog.NewPrettyFormatter(writer).Options(xlog.FormatSkipTime, xlog.FormatNoCaller))

			r, _ := http.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			WriteJSON(w, r, tc.err)
			assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
			assert.Equal(t, tc.exp, w.Body.String())

			assert.Equal(t, tc.log, b.String())
		})
	}
}

func TestNewRequest(t *testing.T) {
	m := map[string]string{
		"key": "value",
	}
	tcases := []struct {
		req interface{}
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
			body, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Equal(t, tc.exp, string(body))
		})
	}
}
