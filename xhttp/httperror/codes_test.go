package httperror_test

import (
	"net/http"
	"testing"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/stretchr/testify/assert"
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
		{httperror.RequestTooLarge("1"), http.StatusBadRequest, "request_too_large: 1"},
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
