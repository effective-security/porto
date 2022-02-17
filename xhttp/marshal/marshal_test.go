package marshal

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	}{
		{httperror.NotFound("foo"), `{"code":"not_found","message":"foo"}`},
		{httperror.Unexpected("bar"), `{"code":"unexpected","message":"bar"}`},
		{errors.Errorf("generic"), `{"code":"unexpected","message":"generic"}`},
		{fmt.Errorf("fmt"), `{"code":"unexpected","message":"fmt"}`},
		{errors.WithMessage(httperror.Unexpected("bar"), "wrapped"), `{"code":"unexpected","message":"bar"}`},
	}

	for i, tc := range tcases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			WriteJSON(w, r, tc.err)
			assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
			assert.Equal(t, tc.exp, w.Body.String())
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
