package httperror

import (
	"context"
	goerrors "errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/effective-security/porto/x/slices"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/pberror"
	"github.com/ugorji/go/codec"
	"google.golang.org/grpc/status"
)

// Error represents a single error from API.
type Error struct {
	// HTTPStatus contains the HTTP status code that should be used for this error
	HTTPStatus int `json:"-"`

	// Code identifies the particular error condition [for programatic consumers]
	Code string `json:"code"`

	// RequestID identifies the request ID
	RequestID string `json:"request_id,omitempty"`

	// Message is an textual description of the error
	Message string `json:"message"`

	// Cause is the original error
	cause error `json:"-"`
}

// New returns Error instance, building the message string along the way
func New(status int, code string, msgFormat string, vals ...interface{}) *Error {
	return &Error{
		HTTPStatus: status,
		Code:       code,
		Message:    fmt.Sprintf(msgFormat, vals...),
	}
}

// NewFromPb returns Error instance, from gRPC error
func NewFromPb(err error) *Error {
	if e, ok := err.(*Error); ok {
		return e
	}
	if st, ok := status.FromError(err); ok {
		hs := statusCode[st.Code()]
		return &Error{
			HTTPStatus: hs,
			Code:       httpCode[hs],
			Message:    st.Message(),
			RequestID:  pberror.CorrelationID(err),
			//cause:      errors.WithStack(err),
		}
	}

	return New(http.StatusInternalServerError, CodeUnexpected, err.Error()).WithCause(err)
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

// ManyError identifies many errors from API.
type ManyError struct {
	// HTTPStatus contains the HTTP status code that should be used for this error
	HTTPStatus int `json:"-"`

	// Code identifies the particular error condition [for programatic consumers]
	Code string `json:"code,omitempty"`

	// RequestID identifies the request ID
	RequestID string `json:"request_id,omitempty"`

	// Message is an textual description of the error
	Message string `json:"message,omitempty"`

	Errors map[string]*Error `json:"errors,omitempty"`

	// Cause is the first original error
	cause error `json:"-"`
}

func (m *ManyError) Error() string {
	if m == nil {
		return "nil"
	}
	if m.Code != "" {
		if m.RequestID != "" {
			return fmt.Sprintf("request %s: %s: %s", m.RequestID, m.Code, m.Message)
		}
		return fmt.Sprintf("%s: %s", m.Code, m.Message)
	}

	var errs []string
	for _, e := range m.Errors {
		errs = append(errs, e.Error())
	}

	return strings.Join(errs, ";")
}

// CorrelationID implements the Correlation interface,
// and returns request ID
func (m *ManyError) CorrelationID() string {
	return m.RequestID
}

// Cause returns original error
func (m *ManyError) Cause() error {
	return m.cause
}

// NewMany builds new ManyError instance, build message string along the way
func NewMany(status int, code string, msgFormat string, vals ...interface{}) *ManyError {
	return &ManyError{
		HTTPStatus: status,
		Code:       code,
		Message:    fmt.Sprintf(msgFormat, vals...),
		Errors:     make(map[string]*Error),
	}
}

// Add a single error to ManyError
func (m *ManyError) Add(key string, err error) *ManyError {
	if m == nil {
		m = new(ManyError)
	}
	if m.Errors == nil {
		m.Errors = make(map[string]*Error)
	}
	if m.cause == nil {
		m.cause = err
	}
	if gErr, ok := err.(*Error); ok {
		m.Errors[key] = gErr
	} else {
		m.Errors[key] = &Error{Code: CodeUnexpected, Message: err.Error(), cause: err}
	}
	return m
}

// HasErrors check if ManyError has any nested error associated with it.
func (m *ManyError) HasErrors() bool {
	return len(m.Errors) > 0
}

// WriteHTTPResponse implements how to serialize this error into a HTTP Response
func (e *Error) WriteHTTPResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(e.HTTPStatus)
	if e.RequestID == "" {
		e.RequestID = correlation.ID(r.Context())
	}
	codec.NewEncoder(w, encoderHandle(shouldPrettyPrint(r))).Encode(e)
}

// WriteHTTPResponse implements how to serialize this error into a HTTP Response
func (m *ManyError) WriteHTTPResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(m.HTTPStatus)
	if m.RequestID == "" {
		m.RequestID = correlation.ID(r.Context())
	}
	codec.NewEncoder(w, encoderHandle(shouldPrettyPrint(r))).Encode(m)
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
	return statusCode[status.Code(err)]
}
