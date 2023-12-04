package httperror_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrorCorrelation(t *testing.T) {
	ctx := correlation.WithID(context.Background())
	cid := correlation.ID(ctx)
	assert.NotEmpty(t, cid)
	ne2 := httperror.NewFromCtx(ctx, http.StatusBadRequest, httperror.CodeInvalidJSON, "some error")
	assert.Equal(t, fmt.Sprintf("request %s: invalid_json: some error", cid), ne2.Error())
	assert.Equal(t, cid, httperror.CorrelationID(ne2))
	rs := ne2.GRPCStatus()
	assert.Equal(t, "rpc error: code = InvalidArgument desc = some error", rs.String())
}

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

	ctx := correlation.WithID(context.Background())
	cid := correlation.ID(ctx)
	assert.NotEmpty(t, cid)
	e.WithContext(ctx)

	assert.Equal(t, fmt.Sprintf("request %s: invalid_json: Bob", cid), e.Error())

	e = e.WithCause(errors.New("some other error"))
	assert.EqualError(t, e, fmt.Sprintf("request %s: invalid_json: Bob", cid))
}

func TestError_Unwrap(t *testing.T) {
	e := httperror.New(http.StatusBadRequest, httperror.CodeInvalidJSON, "Bob")
	assert.Equal(t, "invalid_json: Bob", e.Error())
	assert.Nil(t, e.Unwrap())

	e = e.WithCause(errors.New("some other error"))
	assert.EqualError(t, e.Unwrap(), "some other error")

	e = e.WithCause(errors.WithMessage(errors.New("some other error"), "wrapped"))
	assert.EqualError(t, e.Unwrap(), "some other error")
}

func TestError_Nil(t *testing.T) {
	var e *httperror.Error
	assert.Nil(t, e)
	assert.Equal(t, "nil", e.Error())
}

func TestError_ManyErrorIsError(t *testing.T) {
	oerr := errors.New("original")
	err := httperror.NewMany(http.StatusTooManyRequests, httperror.CodeRateLimitExceeded, "There were 42 errors!").
		WithCause(oerr)
	var _ error = err // won't compile if ManyError doesn't impl error
	assert.Equal(t, "rate_limit_exceeded: There were 42 errors!", err.Error())
	err.RequestID = "123"
	assert.Equal(t, "request 123: rate_limit_exceeded: There were 42 errors!", err.Error())
	assert.Equal(t, err.RequestID, err.CorrelationID())
	assert.Equal(t, codes.ResourceExhausted, err.GRPCStatus().Code())
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

func TestError_IsInvalidRequestError(t *testing.T) {
	assert.True(t, httperror.IsInvalidRequestError(errors.Errorf("invalid ID")))
}

func TestError_IsTimeout(t *testing.T) {
	assert.True(t, httperror.IsTimeout(errors.Errorf("context deadline exceeded")))
	assert.True(t, httperror.IsTimeout(errors.Errorf("request timeout")))
}

func TestError_NewFromPb(t *testing.T) {
	err := httperror.InvalidParam("test")
	assert.Equal(t, err.Error(), httperror.NewFromPb(err).Error())
	assert.Equal(t, codes.InvalidArgument, httperror.GRPCCode(err))
	assert.Equal(t, "test", httperror.GRPCMessage(err))

	err2 := errors.Errorf("test")
	assert.Equal(t, "unexpected: test", httperror.NewFromPb(err2).Error())
	assert.Equal(t, codes.Internal, httperror.GRPCCode(err2))
	assert.Equal(t, "test", httperror.GRPCMessage(err2))

	assert.Equal(t, "unavailable: request timed out", httperror.NewFromPb(ErrGRPCTimeout).Error())
}

func TestError_Status(t *testing.T) {
	assert.Equal(t, http.StatusOK, httperror.Status(nil))
	err1 := httperror.Status(httperror.NotFound("test"))
	assert.Equal(t, http.StatusNotFound, err1)
	err2 := httperror.Status(status.New(codes.NotFound, "test").Err())
	assert.Equal(t, http.StatusNotFound, err2)
	assert.Equal(t, http.StatusInternalServerError, httperror.Status(errors.New("test")))
}

func TestError_Is(t *testing.T) {
	err1 := httperror.NotFound("test")
	err2 := status.New(codes.NotFound, "test").Err()
	err3 := httperror.NotFound("test").WithCause(err2)
	assert.False(t, err1.Is(err2))
	assert.True(t, err1.Is(err3))

	assert.EqualError(t, err3.Cause(), "rpc error: code = NotFound desc = test")
}

func TestError_Wrap(t *testing.T) {
	werr1 := httperror.Wrap(errors.New("no rows"), "wrapped")
	assert.EqualError(t, werr1, "not_found: wrapped")
	werr1s := httperror.Wrap(errors.New("no rows"))
	assert.EqualError(t, werr1s, "not_found: no rows")

	err := status.New(codes.NotFound, "no rows in result set").Err()
	werr2 := httperror.Wrap(err, "wrapped")
	assert.EqualError(t, werr2, "not_found: wrapped")
	werr2s := httperror.Wrap(err)
	assert.EqualError(t, werr2s, "not_found: no rows in result set")

	werr3 := httperror.Wrap(werr2, "wrapped2")
	assert.EqualError(t, werr3, "not_found: wrapped2")
	assert.EqualError(t, werr3.Unwrap(), "rpc error: code = NotFound desc = no rows in result set")

	werr3s := httperror.Wrap(werr2s)
	assert.EqualError(t, werr3s, "not_found: no rows in result set")

	many := httperror.NewMany(werr1.HTTPStatus, werr1.Code, werr1.Message).WithCause(errors.New("many cause"))
	many.Add("werr1", werr1)
	assert.EqualError(t, many, "not_found: wrapped")
	werr4 := httperror.Wrap(many, "wrappedMany")
	assert.EqualError(t, werr4, "not_found: wrappedMany")
	assert.EqualError(t, werr4.Unwrap(), many.Error())

	ctx := correlation.WithID(context.Background())
	cid := correlation.ID(ctx)
	assert.NotEmpty(t, cid)

	werr4 = httperror.WrapWithCtx(ctx, werr3, "wrapped%d", 3)
	assert.EqualError(t, werr4, fmt.Sprintf("request %s: not_found: wrapped3", cid))
	assert.EqualError(t, werr4.Unwrap(), "rpc error: code = NotFound desc = no rows in result set")
	werr4s := httperror.WrapWithCtx(ctx, werr3)
	assert.EqualError(t, werr4s, fmt.Sprintf("request %s: not_found: wrapped2", cid))

	werr5 := httperror.WrapWithCtx(ctx, nil, "wrapped nil")
	assert.EqualError(t, werr5, fmt.Sprintf("request %s: unexpected: wrapped nil", cid))
	assert.Nil(t, werr5.Unwrap())

	werr6 := httperror.WrapWithCtx(ctx, werr5, "wrapped 5")
	assert.EqualError(t, werr6, fmt.Sprintf("request %s: unexpected: wrapped 5", cid))
	assert.EqualError(t, werr6.Unwrap(), werr5.Error())

	werr6s := httperror.WrapWithCtx(ctx, werr5)
	assert.EqualError(t, werr6s, fmt.Sprintf("request %s: unexpected: wrapped nil", cid))
}

func TestGRPCError(t *testing.T) {
	e1 := status.New(codes.PermissionDenied, "permission denied").Err()
	e2 := ErrGRPCPermissionDenied
	e3 := ErrGRPCTimeout

	require.Equal(t, e1.Error(), e2.Error())
	assert.NotEqual(t, e1.Error(), e3.Error())

	_, ok := status.FromError(e1)
	assert.True(t, ok)

	ne := httperror.NewGrpcFromCtx(context.Background(), codes.Unavailable, "some error")
	ev4, ok := status.FromError(ne)
	assert.True(t, ok)
	assert.Equal(t, codes.Unavailable, ev4.Code())
	rs := ne.GRPCStatus()
	assert.Equal(t, "rpc error: code = Unavailable desc = some error", rs.String())
	rse := rs.Err()
	assert.Equal(t, codes.Unavailable, httperror.GRPCCode(rse))
	assert.Equal(t, "some error", httperror.GRPCMessage(rse))

	ctx := correlation.WithID(context.Background())
	cid := correlation.ID(ctx)
	assert.NotEmpty(t, cid)
	ne2 := httperror.NewGrpcFromCtx(ctx, codes.Unavailable, "some error")
	assert.Equal(t, fmt.Sprintf("request %s: unavailable: some error", cid), ne2.Error())
	assert.Equal(t, cid, httperror.CorrelationID(ne2))
	rs = ne2.GRPCStatus()
	assert.Equal(t, "rpc error: code = Unavailable desc = some error", rs.String())

	ne = httperror.NewGrpc(codes.Unavailable, "some error")
	ev4, ok = status.FromError(ne)
	assert.True(t, ok)
	assert.Equal(t, codes.Unavailable, ev4.Code())
}

func TestIsNotFoundError(t *testing.T) {
	assert.True(t, httperror.IsSQLNotFoundError(sql.ErrNoRows))
	assert.True(t, httperror.IsSQLNotFoundError(errors.WithMessage(errors.New("sql: no rows in result set"), "failed")))
	assert.False(t, httperror.IsSQLNotFoundError(nil))
	assert.False(t, httperror.IsInvalidModel(nil))
}

// grpc error
var (
	ErrGRPCTimeout          = status.New(codes.Unavailable, "request timed out").Err()
	ErrGRPCPermissionDenied = status.New(codes.PermissionDenied, "permission denied").Err()
	ErrGRPCInvalidArgument  = status.New(codes.InvalidArgument, "invalid argument").Err()
)
