package httperror

import (
	"context"
	goerrors "errors"
	"fmt"
	"net/http"

	"github.com/effective-security/porto/x/slices"
	"github.com/effective-security/porto/x/xdb"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/ugorji/go/codec"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Error represents a single error from API.
type Error struct {
	// HTTPStatus contains the HTTP status code that should be used for this error
	HTTPStatus int `json:"-"`

	RPCStatus codes.Code `json:"-"`

	// Code identifies the particular error condition [for programatic consumers]
	Code string `json:"code"`

	// RequestID identifies the request ID
	RequestID string `json:"request_id,omitempty"`

	// Message is an textual description of the error
	Message string `json:"message"`

	// Cause is the original error
	cause error `json:"-"`

	ctx context.Context `json:"-"`
}

// New returns Error instance, building the message string along the way
func New(status int, code string, msgFormat string, vals ...interface{}) *Error {
	return &Error{
		HTTPStatus: status,
		RPCStatus:  statusCode[code],
		Code:       code,
		Message:    fmt.Sprintf(msgFormat, vals...),
	}
}

// NewFromCtx returns Error instance, building the message string along the way
func NewFromCtx(ctx context.Context, status int, code string, msgFormat string, vals ...interface{}) *Error {
	e := &Error{
		HTTPStatus: status,
		RPCStatus:  statusCode[code],
		Code:       code,
		Message:    fmt.Sprintf(msgFormat, vals...),
		ctx:        ctx,
	}
	if v := correlation.Value(ctx); v != nil {
		e.RequestID = v.ID
	}

	return e
}

// WithContext adds the context
func (e *Error) WithContext(ctx context.Context) *Error {
	if v := correlation.Value(ctx); v != nil {
		e.RequestID = v.ID
	}
	e.ctx = ctx
	return e
}

// WithCause adds the cause error
func (e *Error) WithCause(err error) *Error {
	e.cause = err
	return e
}

// CorrelationID implements the Correlation interface,
// and returns request ID
func (e *Error) CorrelationID() string {
	return e.RequestID
}

// Error implements the standard error interface
func (e *Error) Error() string {
	if e == nil {
		return "nil"
	}
	if e.RequestID != "" {
		return fmt.Sprintf("request %s: %s: %s", e.RequestID, e.Code, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Cause returns original error
func (e *Error) Cause() error {
	return e.cause
}

// Unwrap returns unwrapped error
func (e *Error) Unwrap() error {
	if e.cause != nil {
		unwrapped := goerrors.Unwrap(e.cause)
		if unwrapped != nil {
			return unwrapped
		}
		return e.cause
	}
	return e
}

// Is implements future error.Is functionality.
// A Error is equivalent if the code and message are identical.
func (e *Error) Is(target error) bool {
	tse, ok := target.(*Error)
	if !ok {
		return false
	}
	return tse.Code == e.Code && tse.Message == e.Message
}

// InvalidParam returns Error instance with InvalidParam code
func InvalidParam(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeInvalidParam, msgFormat, vals...)
}

// InvalidJSON returns Error instance with InvalidJSON code
func InvalidJSON(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeInvalidJSON, msgFormat, vals...)
}

// BadNonce returns Error instance with BadNonce code
func BadNonce(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeBadNonce, msgFormat, vals...)
}

// InvalidRequest returns Error instance with InvalidRequest code
func InvalidRequest(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeInvalidRequest, msgFormat, vals...)
}

// Malformed returns Error instance with Malformed code
func Malformed(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeMalformed, msgFormat, vals...)
}

// InvalidContentType returns Error instance with InvalidContentType code
func InvalidContentType(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeInvalidContentType, msgFormat, vals...)
}

// ContentLengthRequired returns Error instance with ContentLengthRequired code
func ContentLengthRequired() *Error {
	return New(http.StatusBadRequest, CodeContentLengthRequired, "Content-Length header not provided")
}

// NotFound returns Error instance with NotFound code
func NotFound(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusNotFound, CodeNotFound, msgFormat, vals...)
}

// RequestTooLarge returns Error instance with RequestTooLarge code
func RequestTooLarge(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeRequestTooLarge, msgFormat, vals...)
}

// FailedToReadRequestBody returns Error instance with FailedToReadRequestBody code
func FailedToReadRequestBody(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusInternalServerError, CodeFailedToReadRequestBody, msgFormat, vals...)
}

// RateLimitExceeded returns Error instance with RateLimitExceeded code
func RateLimitExceeded(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusTooManyRequests, CodeRateLimitExceeded, msgFormat, vals...)
}

// TooEarly returns Error instance with TooEarly code
func TooEarly(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusTooEarly, CodeTooEarly, msgFormat, vals...)
}

// Unexpected returns Error instance with Unexpected code
func Unexpected(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusInternalServerError, CodeUnexpected, msgFormat, vals...)
}

// Forbidden returns Error instance with Forbidden code
func Forbidden(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusForbidden, CodeForbidden, msgFormat, vals...)
}

// Unauthorized returns Error instance with Unauthorized code
func Unauthorized(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusUnauthorized, CodeUnauthorized, msgFormat, vals...)
}

// AccountNotFound returns Error instance with AccountNotFound code
func AccountNotFound(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusForbidden, CodeAccountNotFound, msgFormat, vals...)
}

// NotReady returns Error instance with NotReady code
func NotReady(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusServiceUnavailable, CodeNotReady, msgFormat, vals...)
}

// Conflict returns Error instance with Conflict code
func Conflict(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusConflict, CodeConflict, msgFormat, vals...)
}

// Timeout returns Error instance with RequestTimeout code
func Timeout(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusRequestTimeout, CodeTimeout, msgFormat, vals...)
}

// Wrap returns Error instance with NotFound, Timeout or Internal code,
// depending on the error from DB
func Wrap(err error, msgFormat string, vals ...interface{}) *Error {
	if unwrapped := goerrors.Unwrap(err); unwrapped != nil {
		err = unwrapped
	}

	switch e := err.(type) {
	case *Error:
		return New(e.HTTPStatus, e.Code, msgFormat, vals...).WithCause(e.cause)
	case *ManyError:
		return New(e.HTTPStatus, e.Code, msgFormat, vals...).WithCause(e.cause)
	}

	if xdb.IsNotFoundError(err) {
		return NotFound(msgFormat, vals...).WithCause(err)
	}
	if IsTimeout(err) {
		return Timeout(msgFormat, vals...).WithCause(err)
	}
	return Unexpected(msgFormat, vals...).WithCause(err)
}

// WrapWithCtx returns wrapped Error with Context
func WrapWithCtx(ctx context.Context, err error, msgFormat string, vals ...interface{}) *Error {
	return Wrap(err, msgFormat, vals...).WithContext(ctx)
}

// IsTimeout returns true for timeout error
func IsTimeout(err error) bool {
	str := err.Error()
	return goerrors.Is(err, context.DeadlineExceeded) ||
		goerrors.Is(err, context.Canceled) ||
		slices.StringContainsOneOf(str, timeoutErrors)
}

var timeoutErrors = []string{"timeout", "deadline"}

// Status returns HTTP status from error
func Status(err error) int {
	if err == nil {
		return http.StatusOK
	}

	switch e := err.(type) {
	case *Error:
		return e.HTTPStatus
	case *ManyError:
		return e.HTTPStatus
	}
	code := status.Code(err)
	return codeStatus[code]
}

// WriteHTTPResponse implements how to serialize this error into a HTTP Response
func (e *Error) WriteHTTPResponse(w http.ResponseWriter, r *http.Request) {
	// TODO: check r.Accept
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(e.HTTPStatus)
	if e.RequestID == "" {
		e.RequestID = correlation.ID(r.Context())
	}
	_ = codec.NewEncoder(w, encoderHandle(shouldPrettyPrint(r))).Encode(e)
}
