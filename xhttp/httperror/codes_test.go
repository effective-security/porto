package httperror_test

import (
	"net/http"
	"testing"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Test_ErrorCodes(t *testing.T) {
	assert.Equal(t, "account_not_found", httperror.CodeAccountNotFound)
	assert.Equal(t, "bad_nonce", httperror.CodeBadNonce)
	assert.Equal(t, "conflict", httperror.CodeConflict)
	assert.Equal(t, "connection", httperror.CodeConnection)
	assert.Equal(t, "content_length_required", httperror.CodeContentLengthRequired)
	assert.Equal(t, "forbidden", httperror.CodeForbidden)
	assert.Equal(t, "invalid_content_type", httperror.CodeInvalidContentType)
	assert.Equal(t, "invalid_json", httperror.CodeInvalidJSON)
	assert.Equal(t, "invalid_parameter", httperror.CodeInvalidParam)
	assert.Equal(t, "invalid_request", httperror.CodeInvalidRequest)
	assert.Equal(t, "malformed", httperror.CodeMalformed)
	assert.Equal(t, "not_found", httperror.CodeNotFound)
	assert.Equal(t, "not_ready", httperror.CodeNotReady)
	assert.Equal(t, "rate_limit_exceeded", httperror.CodeRateLimitExceeded)
	assert.Equal(t, "request_body", httperror.CodeFailedToReadRequestBody)
	assert.Equal(t, "request_too_large", httperror.CodeRequestTooLarge)
	assert.Equal(t, "unauthorized", httperror.CodeUnauthorized)
	assert.Equal(t, "unexpected", httperror.CodeUnexpected)
}

func Test_StatusCodes(t *testing.T) {
	tcases := []struct {
		httpErr   *httperror.Error
		expStatus int
		expMsg    string
	}{
		{httperror.InvalidParam("1"), http.StatusBadRequest, "invalid_parameter: 1"},
		{httperror.InvalidJSON("1"), http.StatusBadRequest, "invalid_json: 1"},
		{httperror.BadNonce("1"), http.StatusBadRequest, "bad_nonce: 1"},
		{httperror.InvalidRequest("1"), http.StatusBadRequest, "invalid_request: 1"},
		{httperror.Malformed("1"), http.StatusBadRequest, "malformed: 1"},
		{httperror.InvalidContentType("1"), http.StatusBadRequest, "invalid_content_type: 1"},
		{httperror.ContentLengthRequired(), http.StatusBadRequest, "content_length_required: Content-Length header not provided"},
		{httperror.NotFound("1"), http.StatusNotFound, "not_found: 1"},
		{httperror.RequestTooLarge("1"), http.StatusRequestEntityTooLarge, "request_too_large: 1"},
		{httperror.FailedToReadRequestBody("1"), http.StatusInternalServerError, "request_body: 1"},
		{httperror.RateLimitExceeded("1"), http.StatusTooManyRequests, "rate_limit_exceeded: 1"},
		{httperror.TooEarly("1"), http.StatusTooEarly, "too_early: 1"},
		{httperror.Unexpected("1"), http.StatusInternalServerError, "unexpected: 1"},
		{httperror.Forbidden("1"), http.StatusForbidden, "forbidden: 1"},
		{httperror.Unauthorized("1"), http.StatusUnauthorized, "unauthorized: 1"},
		{httperror.AccountNotFound("1"), http.StatusForbidden, "account_not_found: 1"},
		{httperror.NotReady("1"), http.StatusServiceUnavailable, "not_ready: 1"},
		{httperror.Conflict("1"), http.StatusConflict, "conflict: 1"},
		{httperror.Timeout("1"), http.StatusRequestTimeout, "timeout: 1"},
	}
	for _, tc := range tcases {
		t.Run(tc.httpErr.Code, func(t *testing.T) {
			assert.Equal(t, tc.expStatus, tc.httpErr.HTTPStatus)
			assert.Equal(t, tc.expMsg, tc.httpErr.Error())
			assert.NotNil(t, tc.httpErr.GRPCStatus())
		})
	}
}

func Test_OAuthError(t *testing.T) {
	assert.EqualError(t, httperror.FromOAuth("1", "2"), "1: 2")
	assert.EqualError(t, httperror.FromOAuth("invalid_request", "aaa"), "invalid_request: aaa")
	assert.EqualError(t, httperror.FromOAuth("temporarily_unavailable", "aaa"), "temporarily_unavailable: aaa")
	assert.EqualError(t, httperror.FromOAuth("server_error", "aaa"), "server_error: aaa")
	assert.EqualError(t, httperror.FromOAuth("invalid_client", "aaa"), "invalid_client: aaa")
}

func Test_AuthStatusMapping(t *testing.T) {
	t.Parallel()
	// Google API mapping: Unauthenticated is 401, PermissionDenied is 403.
	assert.Equal(t, http.StatusUnauthorized, httperror.HTTPStatusFromRPC(codes.Unauthenticated))
	assert.Equal(t, http.StatusForbidden, httperror.HTTPStatusFromRPC(codes.PermissionDenied))
	assert.Equal(t, codes.Unauthenticated, httperror.Unauthorized("1").RPCStatus)
	assert.Equal(t, codes.PermissionDenied, httperror.Forbidden("1").RPCStatus)

	denied := httperror.NewFromPb(status.Error(codes.PermissionDenied, "denied"))
	assert.Equal(t, http.StatusForbidden, denied.HTTPStatus)
	assert.Equal(t, httperror.CodeForbidden, denied.Code)
	assert.Equal(t, http.StatusForbidden, httperror.Status(status.Error(codes.PermissionDenied, "denied")))

	unauthenticated := httperror.NewFromPb(status.Error(codes.Unauthenticated, "who"))
	assert.Equal(t, http.StatusUnauthorized, unauthenticated.HTTPStatus)
	assert.Equal(t, httperror.CodeUnauthorized, unauthenticated.Code)
	assert.Equal(t, http.StatusUnauthorized, httperror.Status(status.Error(codes.Unauthenticated, "who")))

	assert.Equal(t, http.StatusForbidden, httperror.NewGrpc(codes.PermissionDenied, "denied").HTTPStatus)
	assert.Equal(t, http.StatusUnauthorized, httperror.NewGrpc(codes.Unauthenticated, "who").HTTPStatus)
}

func Test_RPCCodeToHTTPStatus(t *testing.T) {
	t.Parallel()
	// gRPC code → HTTP status and httperror code (codeStatus, then httpCode).
	// Several gRPC codes share one HTTP status; NewFromPb keeps the gRPC code
	// on RPCStatus. A bare FailedPrecondition is 400 bad_request: 409 is
	// AlreadyExists and Aborted, and 500 would label it unexpected.
	cases := []struct {
		rpc        codes.Code
		httpStatus int
		code       string
	}{
		{codes.OK, http.StatusOK, ""},
		{codes.Canceled, http.StatusRequestTimeout, "request_timeout"},
		{codes.Unknown, http.StatusInternalServerError, httperror.CodeUnexpected},
		{codes.InvalidArgument, http.StatusBadRequest, "bad_request"},
		{codes.DeadlineExceeded, http.StatusRequestTimeout, "request_timeout"},
		{codes.NotFound, http.StatusNotFound, httperror.CodeNotFound},
		{codes.AlreadyExists, http.StatusConflict, httperror.CodeConflict},
		{codes.PermissionDenied, http.StatusForbidden, httperror.CodeForbidden},
		{codes.ResourceExhausted, http.StatusTooManyRequests, "too_many_requests"},
		{codes.FailedPrecondition, http.StatusBadRequest, "bad_request"},
		{codes.Aborted, http.StatusConflict, httperror.CodeConflict},
		{codes.OutOfRange, http.StatusBadRequest, "bad_request"},
		{codes.Unimplemented, http.StatusNotImplemented, "not_implemented"},
		{codes.Internal, http.StatusInternalServerError, httperror.CodeUnexpected},
		{codes.Unavailable, http.StatusServiceUnavailable, "unavailable"},
		{codes.DataLoss, http.StatusInternalServerError, httperror.CodeUnexpected},
		{codes.Unauthenticated, http.StatusUnauthorized, httperror.CodeUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.rpc.String(), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.httpStatus, httperror.HTTPStatusFromRPC(tc.rpc))

			viaGrpc := httperror.NewGrpc(tc.rpc, "msg")
			assert.Equal(t, tc.httpStatus, viaGrpc.HTTPStatus)
			assert.Equal(t, tc.code, viaGrpc.Code)
			assert.Equal(t, tc.rpc, viaGrpc.RPCStatus)

			if tc.rpc == codes.OK {
				return
			}
			pbErr := status.Error(tc.rpc, "org state")
			got := httperror.NewFromPb(pbErr)
			assert.Equal(t, tc.httpStatus, got.HTTPStatus)
			assert.Equal(t, tc.code, got.Code)
			assert.Equal(t, tc.rpc, got.RPCStatus)
			assert.Equal(t, "org state", got.Message)
			assert.Equal(t, tc.httpStatus, httperror.Status(pbErr))
		})
	}

	assert.Equal(t, 0, httperror.HTTPStatusFromRPC(codes.Code(99)))
}

func Test_ErrorCodeToRPCStatus(t *testing.T) {
	t.Parallel()
	// httperror code → gRPC code (statusCode), the reverse of Test_RPCCodeToHTTPStatus.
	cases := []struct {
		code string
		rpc  codes.Code
	}{
		{httperror.CodeAccountNotFound, codes.NotFound},
		{httperror.CodeBadNonce, codes.InvalidArgument},
		{httperror.CodeConflict, codes.AlreadyExists},
		{httperror.CodeConnection, codes.Unknown},
		{httperror.CodeContentLengthRequired, codes.InvalidArgument},
		{httperror.CodeFailedToReadRequestBody, codes.InvalidArgument},
		{httperror.CodeForbidden, codes.PermissionDenied},
		{httperror.CodeInvalidContentType, codes.InvalidArgument},
		{httperror.CodeInvalidJSON, codes.InvalidArgument},
		{httperror.CodeInvalidParam, codes.InvalidArgument},
		{httperror.CodeInvalidRequest, codes.InvalidArgument},
		{httperror.CodeMalformed, codes.InvalidArgument},
		{httperror.CodeNotFound, codes.NotFound},
		{httperror.CodeNotReady, codes.Unavailable},
		{httperror.CodeRateLimitExceeded, codes.ResourceExhausted},
		{httperror.CodeRequestFailed, codes.Unknown},
		{httperror.CodeRequestTooLarge, codes.ResourceExhausted},
		{httperror.CodeTimeout, codes.DeadlineExceeded},
		{httperror.CodeTooEarly, codes.ResourceExhausted},
		{httperror.CodeUnauthorized, codes.Unauthenticated},
		{httperror.CodeUnexpected, codes.Internal},

		{"bad_request", codes.InvalidArgument},
		{"payment_required", codes.PermissionDenied},
		{"not_allowed", codes.InvalidArgument},
		{"not_acceptable", codes.InvalidArgument},
		{"auth_required", codes.Unauthenticated},
		{"request_timeout", codes.Canceled},
		{"gone", codes.NotFound},
		{"length_required", codes.InvalidArgument},
		{"precondition_failed", codes.FailedPrecondition},
		{"too_large", codes.InvalidArgument},
		{"uri_too_long", codes.InvalidArgument},
		{"unsupported_media_type", codes.InvalidArgument},
		{"expectation_failed", codes.InvalidArgument},
		{"teapot", codes.InvalidArgument},
		{"misdirected", codes.InvalidArgument},
		{"unprocessable", codes.InvalidArgument},
		{"locked", codes.FailedPrecondition},
		{"failed_dependency", codes.FailedPrecondition},
		{"upgrade_required", codes.FailedPrecondition},
		{"precondition_required", codes.FailedPrecondition},
		{"too_many_requests", codes.ResourceExhausted},
		{"legal_reason", codes.PermissionDenied},
		{"not_implemented", codes.Unimplemented},
		{"bad_gateway", codes.Unavailable},
		{"unavailable", codes.Unavailable},
		{"gateway_timeout", codes.Unavailable},
		{"not_supported", codes.Unimplemented},
		{"insufficient_storage", codes.ResourceExhausted},
		{"loop_detected", codes.ResourceExhausted},
		{"not_extended", codes.Unimplemented},
		{"authentication_required", codes.Unauthenticated},

		{"no_such_code", codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			got := httperror.New(http.StatusBadRequest, tc.code, "m")
			assert.Equal(t, tc.rpc, got.RPCStatus)
			assert.Equal(t, tc.rpc, got.GRPCStatus().Code())
		})
	}
}
