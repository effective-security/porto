package httperror

import (
	"context"
	goerrors "errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xdb"
	"github.com/ugorji/go/codec"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Error represents a single error from API.
type Error struct {
	// HTTPStatus contains the HTTP status code that should be used for this error
	HTTPStatus int `json:"-"`

	// RPCStatus is the gRPC status code returned by GRPCStatus; derived from
	// Code for the well-known codes, codes.OK (0) for unknown codes.
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

// New returns an Error with the given HTTP status and code, formatting the
// message with fmt.Sprintf. RPCStatus is looked up from code; use one of the
// Code* constants for a meaningful gRPC mapping.
func New(status int, code string, msgFormat string, vals ...any) *Error {
	return &Error{
		HTTPStatus: status,
		RPCStatus:  statusCode[code],
		Code:       code,
		Message:    fmt.Sprintf(msgFormat, vals...),
	}
}

// NewFromCtx is New plus WithContext: the RequestID is taken from the
// correlation ID in ctx.
func NewFromCtx(ctx context.Context, status int, code string, msgFormat string, vals ...any) *Error {
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

// WithContext records ctx on the error and copies its correlation ID into
// RequestID. It mutates and returns the receiver.
func (e *Error) WithContext(ctx context.Context) *Error {
	if v := correlation.Value(ctx); v != nil {
		e.RequestID = v.ID
	}
	e.ctx = ctx
	return e
}

// WithCause records the underlying error (returned by Cause/Unwrap and
// logged by marshal.WriteJSON). It mutates and returns the receiver.
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

// Cause returns the underlying error set with WithCause, or nil.
func (e *Error) Cause() error {
	return e.cause
}

// Unwrap returns the error one level below the cause when the cause itself
// wraps an error, otherwise the cause. This lets errors.Is/As reach through
// both Error and a cockroachdb/pkg errors wrapper.
func (e *Error) Unwrap() error {
	if e.cause != nil {
		unwrapped := goerrors.Unwrap(e.cause)
		if unwrapped != nil {
			return unwrapped
		}
		return e.cause
	}
	return nil
}

// Is reports whether target is an *Error with identical Code and Message,
// for use with errors.Is.
func (e *Error) Is(target error) bool {
	tse, ok := target.(*Error)
	if !ok {
		return false
	}
	return tse.Code == e.Code && tse.Message == e.Message
}

// InvalidParam returns Error instance with InvalidParam code
func InvalidParam(msgFormat string, vals ...any) *Error {
	return New(http.StatusBadRequest, CodeInvalidParam, msgFormat, vals...)
}

// InvalidJSON returns Error instance with InvalidJSON code
func InvalidJSON(msgFormat string, vals ...any) *Error {
	return New(http.StatusBadRequest, CodeInvalidJSON, msgFormat, vals...)
}

// BadNonce returns Error instance with BadNonce code
func BadNonce(msgFormat string, vals ...any) *Error {
	return New(http.StatusBadRequest, CodeBadNonce, msgFormat, vals...)
}

// InvalidRequest returns Error instance with InvalidRequest code
func InvalidRequest(msgFormat string, vals ...any) *Error {
	return New(http.StatusBadRequest, CodeInvalidRequest, msgFormat, vals...)
}

// Malformed returns Error instance with Malformed code
func Malformed(msgFormat string, vals ...any) *Error {
	return New(http.StatusBadRequest, CodeMalformed, msgFormat, vals...)
}

// InvalidContentType returns Error instance with InvalidContentType code
func InvalidContentType(msgFormat string, vals ...any) *Error {
	return New(http.StatusBadRequest, CodeInvalidContentType, msgFormat, vals...)
}

// ContentLengthRequired returns Error instance with ContentLengthRequired code
func ContentLengthRequired() *Error {
	return New(http.StatusBadRequest, CodeContentLengthRequired, "Content-Length header not provided")
}

// NotFound returns Error instance with NotFound code
func NotFound(msgFormat string, vals ...any) *Error {
	return New(http.StatusNotFound, CodeNotFound, msgFormat, vals...)
}

// RequestTooLarge returns an HTTP 413 error with the request_too_large code.
func RequestTooLarge(msgFormat string, vals ...any) *Error {
	return New(http.StatusRequestEntityTooLarge, CodeRequestTooLarge, msgFormat, vals...)
}

// FailedToReadRequestBody returns Error instance with FailedToReadRequestBody code
func FailedToReadRequestBody(msgFormat string, vals ...any) *Error {
	return New(http.StatusInternalServerError, CodeFailedToReadRequestBody, msgFormat, vals...)
}

// RateLimitExceeded returns Error instance with RateLimitExceeded code
func RateLimitExceeded(msgFormat string, vals ...any) *Error {
	return New(http.StatusTooManyRequests, CodeRateLimitExceeded, msgFormat, vals...)
}

// TooEarly returns Error instance with TooEarly code
func TooEarly(msgFormat string, vals ...any) *Error {
	return New(http.StatusTooEarly, CodeTooEarly, msgFormat, vals...)
}

// Unexpected returns Error instance with Unexpected code
func Unexpected(msgFormat string, vals ...any) *Error {
	return New(http.StatusInternalServerError, CodeUnexpected, msgFormat, vals...)
}

// Forbidden returns Error instance with Forbidden code
func Forbidden(msgFormat string, vals ...any) *Error {
	return New(http.StatusForbidden, CodeForbidden, msgFormat, vals...)
}

// Unauthorized returns Error instance with Unauthorized code
func Unauthorized(msgFormat string, vals ...any) *Error {
	return New(http.StatusUnauthorized, CodeUnauthorized, msgFormat, vals...)
}

// AccountNotFound returns Error instance with AccountNotFound code
func AccountNotFound(msgFormat string, vals ...any) *Error {
	return New(http.StatusForbidden, CodeAccountNotFound, msgFormat, vals...)
}

// NotReady returns Error instance with NotReady code
func NotReady(msgFormat string, vals ...any) *Error {
	return New(http.StatusServiceUnavailable, CodeNotReady, msgFormat, vals...)
}

// Conflict returns Error instance with Conflict code
func Conflict(msgFormat string, vals ...any) *Error {
	return New(http.StatusConflict, CodeConflict, msgFormat, vals...)
}

// Timeout returns Error instance with RequestTimeout code
func Timeout(msgFormat string, vals ...any) *Error {
	return New(http.StatusRequestTimeout, CodeTimeout, msgFormat, vals...)
}

// Wrap converts any error into an *Error. An *Error or *ManyError found via
// errors.As is preserved (returned as is when msgAndArgs is empty); a gRPC
// status error is mapped through HTTPStatusFromRPC; otherwise the error text
// is classified with IsNotFound (404), IsInvalidRequestError (400),
// IsTimeout (408) or Unexpected (500). msgAndArgs optionally override the
// message: a single string, or a format string followed by arguments.
func Wrap(err error, msgAndArgs ...any) *Error {
	e := &Error{}
	if goerrors.As(err, &e) {
		if len(msgAndArgs) == 0 {
			return e
		}
		return New(e.HTTPStatus, e.Code, "%s", errMsg(e.Message, msgAndArgs...)).WithCause(err)
	}
	me := &ManyError{}
	if goerrors.As(err, &me) {
		return New(me.HTTPStatus, me.Code, "%s", errMsg(me.Message, msgAndArgs...)).WithCause(err)
	}

	if se, ok := err.(interface {
		GRPCStatus() *status.Status
	}); ok {
		st := se.GRPCStatus()
		code := st.Code()
		status := codeStatus[code]
		return New(status, httpCode[status], "%s", errMsg(st.Message(), msgAndArgs...)).WithCause(err)
	}

	var errstr string
	if err != nil {
		errstr = err.Error()
	}
	msg := errMsg(errstr, msgAndArgs...)
	if IsNotFound(err, errstr) {
		return NotFound("%s", msg).WithCause(err)
	}
	if IsInvalidRequestError(err, errstr) {
		return InvalidRequest("%s", msg).WithCause(err)
	}
	if IsTimeout(err, errstr) {
		return Timeout("%s", msg).WithCause(err)
	}
	return Unexpected("%s", msg).WithCause(err)
}

// WrapWithCtx is Wrap followed by WithContext(ctx).
func WrapWithCtx(ctx context.Context, err error, msgAndArgs ...any) *Error {
	return Wrap(err, msgAndArgs...).WithContext(ctx)
}

func errMsg(err string, msgAndArgs ...any) string {
	if len(msgAndArgs) == 0 || msgAndArgs == nil {
		return err
	}
	if len(msgAndArgs) == 1 {
		msg := msgAndArgs[0]
		if msgAsStr, ok := msg.(string); ok {
			return msgAsStr
		}
		return fmt.Sprintf("%+v", msg)
	}
	if len(msgAndArgs) > 1 {
		return fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...)
	}
	return err
}

// IsInvalidModel reports whether the error text contains "invalid model".
func IsInvalidModel(err error) bool {
	return err != nil && strings.Contains(err.Error(), "invalid model")
}

// IsInvalidRequestError reports whether err (or any of errStrings) looks
// like a client error, by substring match on "invalid", "Invalid", "bad" or
// "400".
func IsInvalidRequestError(err error, errStrings ...string) bool {
	if err == nil {
		return false
	}
	for _, errString := range errStrings {
		if slices.StringContainsOneOf(errString, invalidErrors) {
			return true
		}
	}
	return slices.StringContainsOneOf(err.Error(), invalidErrors)
}

var invalidErrors = []string{"invalid", "Invalid", "bad", "400"}

// IsTimeout reports whether err is context.DeadlineExceeded or
// context.Canceled, or whether err (or any of errStrings) contains a
// timeout/deadline/cancel substring.
func IsTimeout(err error, errStrings ...string) bool {
	if err == nil {
		return false
	}
	if goerrors.Is(err, context.DeadlineExceeded) ||
		goerrors.Is(err, context.Canceled) {
		return true
	}
	for _, errString := range errStrings {
		if slices.StringContainsOneOf(errString, timeoutErrors) {
			return true
		}
	}

	str := err.Error()
	return slices.StringContainsOneOf(str, timeoutErrors)
}

var timeoutErrors = []string{"timeout", "deadline", "canceling", "canceled", "Timeout"}

// IsNotFound reports whether err is an xdb not-found error, or whether err
// (or any of errStrings) contains "not found", "Not Found" or "404".
func IsNotFound(err error, errStrings ...string) bool {
	if err == nil {
		return false
	}
	if xdb.IsNotFoundError(err) {
		return true
	}
	for _, errString := range errStrings {
		if slices.StringContainsOneOf(errString, notFoundErrors) {
			return true
		}
	}

	str := err.Error()
	return slices.StringContainsOneOf(str, notFoundErrors)
}

var notFoundErrors = []string{"not found", "Not Found", "404"}

// Status returns the HTTP status for err: 200 for nil, HTTPStatus for a
// direct *Error or *ManyError, otherwise the gRPC status code of err mapped
// with HTTPStatusFromRPC (500 for non-status errors).
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

// WriteHTTPResponse writes the error as an application/json body with
// HTTPStatus, pretty-printed when the URL has a "pp" query parameter. If
// RequestID is empty it is filled from the request's correlation ID, which
// mutates the receiver.
func (e *Error) WriteHTTPResponse(w http.ResponseWriter, r *http.Request) {
	// TODO: check r.Accept
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(e.HTTPStatus)
	if e.RequestID == "" {
		e.RequestID = correlation.ID(r.Context())
	}
	_ = codec.NewEncoder(w, encoderHandle(shouldPrettyPrint(r))).Encode(e)
}
