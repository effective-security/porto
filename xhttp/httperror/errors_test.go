package httperror_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/pberror"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestErrorCode_JSON(t *testing.T) {
	v := map[string]string{"foo": httperror.CodeInvalidJSON}
	b, err := json.Marshal(&v)
	require.NoError(t, err, "Unable to marshal to json")
	exp := `{"foo":"invalid_json"}`
	assert.Equal(t, exp, string(b), "Unexpected JSON serializtion of ErrorCode")
}

func TestError_Error(t *testing.T) {
	// compile error if Error doesn't impl error
	var _ error = &httperror.Error{}

	e := httperror.New(http.StatusBadRequest, httperror.CodeInvalidJSON, "Bob")
	assert.Equal(t, "invalid_json: Bob", e.Error())
	e.RequestID = "123"
	assert.Equal(t, "request 123: invalid_json: Bob", e.Error())

	_ = e.WithCause(errors.New("some other error"))
	assert.Equal(t, "request 123: invalid_json: Bob", e.Error())
}

func TestError_Nil(t *testing.T) {
	var e *httperror.Error
	assert.Nil(t, e)
	assert.Equal(t, "nil", e.Error())
}

func TestError_ManyErrorIsError(t *testing.T) {
	err := httperror.NewMany(http.StatusBadRequest, httperror.CodeRateLimitExceeded, "There were 42 errors!")
	var _ error = err // won't compile if ManyError doesn't impl error
	assert.Equal(t, "rate_limit_exceeded: There were 42 errors!", err.Error())
	err.RequestID = "123"
	assert.Equal(t, "request 123: rate_limit_exceeded: There were 42 errors!", err.Error())
}

func TestError_ManyError(t *testing.T) {
	var many *httperror.ManyError
	assert.Nil(t, many)
	assert.Equal(t, "nil", many.Error())

	many = many.Add("testing", errors.Errorf("from nil"))
	require.NotNil(t, many)
	assert.NotNil(t, many.Errors)
	assert.Equal(t, "unexpected: from nil", many.Error())

	many.Code = ""
	assert.NotNil(t, many.Errors)
	assert.Equal(t, "unexpected: from nil", many.Error())
}

func TestError_AddErrorToManyError(t *testing.T) {
	me := httperror.NewMany(http.StatusBadRequest, httperror.CodeRateLimitExceeded, "There were 42 errors!")
	_ = me.Add("one", errors.Errorf("test error 1"))
	assert.Equal(t, 1, len(me.Errors))
	_ = me.Add("two", httperror.New(http.StatusBadRequest, httperror.CodeInvalidJSON, "test error 2"))
	assert.Equal(t, 2, len(me.Errors))
	assert.True(t, me.HasErrors(), "many error contains two errors")
	assert.Contains(t, me.Errors, "one")
	assert.Contains(t, me.Errors, "two")
}

func TestError_AddErrorToNilManyError(t *testing.T) {
	var me httperror.ManyError
	_ = me.Add("one", errors.Errorf("test error 1"))
	assert.Equal(t, 1, len(me.Errors))
	me.Add("two", httperror.New(http.StatusBadRequest, httperror.CodeInvalidJSON, "test error 2"))
	assert.Equal(t, 2, len(me.Errors))
	assert.True(t, me.HasErrors(), "many error contains two errors")
	assert.Contains(t, me.Errors, "one")
	assert.Contains(t, me.Errors, "two")
}

func TestError_WriteHTTPResponse(t *testing.T) {
	single := httperror.New(http.StatusBadRequest, httperror.CodeInvalidJSON, "test error 2")
	single.RequestID = "123"

	many := httperror.NewMany(http.StatusBadRequest, httperror.CodeRateLimitExceeded, "There were 2 errors!")

	_ = many.Add("one", errors.Errorf("test error 1"))
	_ = many.Add("two", httperror.New(http.StatusBadRequest, httperror.CodeInvalidJSON, "test error 2"))

	many.RequestID = "123"
	many.Add("one", errors.Errorf("test error 1"))
	many.Add("two", httperror.New(http.StatusBadRequest, httperror.CodeInvalidJSON, "test error 2"))
	assert.EqualError(t, many.Cause(), "test error 1")

	manyNil := &httperror.ManyError{HTTPStatus: http.StatusBadRequest}
	_ = manyNil.Add("one", errors.Errorf("test error 1"))
	_ = manyNil.Add("two", httperror.New(http.StatusBadRequest, httperror.CodeInvalidJSON, "test error 2"))

	cases := []struct {
		name     string
		err      error
		urlPath  string
		expected string
	}{
		{
			name:     "single_raw_json",
			err:      single,
			urlPath:  "/",
			expected: `{"code":"invalid_json","request_id":"123","message":"test error 2"}`,
		},
		{
			name:    "single_pretty_json",
			err:     single,
			urlPath: "/?pp",
			expected: `{
	"code": "invalid_json",
	"message": "test error 2",
	"request_id": "123"
}`,
		},
		{
			name:    "many_pretty_json",
			err:     many,
			urlPath: "/?pp",
			expected: `{
	"code": "rate_limit_exceeded",
	"errors": {
		"one": {
			"code": "unexpected",
			"message": "test error 1"
		},
		"two": {
			"code": "invalid_json",
			"message": "test error 2"
		}
	},
	"message": "There were 2 errors!",
	"request_id": "123"
}`,
		},
		{
			name:    "manynil_pretty_json",
			err:     manyNil,
			urlPath: "/?pp",
			expected: `{
	"errors": {
		"one": {
			"code": "unexpected",
			"message": "test error 1"
		},
		"two": {
			"code": "invalid_json",
			"message": "test error 2"
		}
	}
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodGet, tc.urlPath, nil)
			require.NoError(t, err)

			switch tc.err.(type) {
			case *httperror.ManyError:
				tc.err.(*httperror.ManyError).WriteHTTPResponse(w, r)
			default:
				tc.err.(*httperror.Error).WriteHTTPResponse(w, r)
			}
			assert.Equal(t, tc.expected, w.Body.String())
		})
	}
}

func TestError_IsTimeout(t *testing.T) {
	assert.True(t, httperror.IsTimeout(errors.Errorf("context deadline exceeded")))
	assert.True(t, httperror.IsTimeout(errors.Errorf("request timeout")))
}

func TestError_NewFromPb(t *testing.T) {
	err := httperror.InvalidParam("test")
	assert.Equal(t, err.Error(), httperror.NewFromPb(err).Error())
	err2 := errors.Errorf("test")
	assert.Equal(t, "unexpected: test", httperror.NewFromPb(err2).Error())

	assert.Equal(t, "unavailable: request timed out", httperror.NewFromPb(pberror.ErrGRPCTimeout).Error())
}

func TestError_Status(t *testing.T) {
	assert.Equal(t, http.StatusOK, httperror.Status(nil))
	assert.Equal(t, http.StatusNotFound, httperror.Status(httperror.NotFound("test")))
	assert.Equal(t, http.StatusNotFound, httperror.Status(pberror.New(codes.NotFound, "test")))
	assert.Equal(t, http.StatusInternalServerError, httperror.Status(errors.New("test")))
}
