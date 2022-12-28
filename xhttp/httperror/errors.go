package httperror

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/ugorji/go/codec"
)

// Error represents a single error from API.
type Error struct {
	// HTTPStatus contains the HTTP status code that should be used for this error
	HTTPStatus int `json:"-"`

	// Code identifies the particular error condition [for programatic consumers]
	Code string `json:"code"`

	// Message is an textual description of the error
	Message string `json:"message"`

	// Cause is the original error
	Cause error `json:"-"`
}

// New builds a new Error instance, building the message string along the way
func New(status int, code string, msgFormat string, vals ...interface{}) *Error {
	return &Error{
		HTTPStatus: status,
		Code:       code,
		Message:    fmt.Sprintf(msgFormat, vals...),
	}
}

// InvalidParam for builds a new Error instance with InvalidParam code
func InvalidParam(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeInvalidParam, msgFormat, vals...)
}

// InvalidJSON for builds a new Error instance with InvalidJSON code
func InvalidJSON(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeInvalidJSON, msgFormat, vals...)
}

// BadNonce for builds a new Error instance with BadNonce code
func BadNonce(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeBadNonce, msgFormat, vals...)
}

// InvalidRequest for builds a new Error instance with InvalidRequest code
func InvalidRequest(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeInvalidRequest, msgFormat, vals...)
}

// Malformed for builds a new Error instance with Malformed code
func Malformed(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeMalformed, msgFormat, vals...)
}

// InvalidContentType for builds a new Error instance with InvalidContentType code
func InvalidContentType(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeInvalidContentType, msgFormat, vals...)
}

// ContentLengthRequired for builds a new Error instance with ContentLengthRequired code
func ContentLengthRequired() *Error {
	return New(http.StatusBadRequest, CodeContentLengthRequired, "Content-Length header not provided")
}

// NotFound for builds a new Error instance with NotFound code
func NotFound(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusNotFound, CodeNotFound, msgFormat, vals...)
}

// RequestTooLarge for builds a new Error instance with RequestTooLarge code
func RequestTooLarge(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusBadRequest, CodeRequestTooLarge, msgFormat, vals...)
}

// FailedToReadRequestBody for builds a new Error instance with FailedToReadRequestBody code
func FailedToReadRequestBody(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusInternalServerError, CodeFailedToReadRequestBody, msgFormat, vals...)
}

// RateLimitExceeded for builds a new Error instance with RateLimitExceeded code
func RateLimitExceeded(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusTooManyRequests, CodeRateLimitExceeded, msgFormat, vals...)
}

// TooEarly for builds a new Error instance with TooEarly code
func TooEarly(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusTooEarly, CodeTooEarly, msgFormat, vals...)
}

// Unexpected for builds a new Error instance with Unexpected code
func Unexpected(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusInternalServerError, CodeUnexpected, msgFormat, vals...)
}

// Forbidden for builds a new Error instance with Forbidden code
func Forbidden(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusForbidden, CodeForbidden, msgFormat, vals...)
}

// Unauthorized for builds a new Error instance with Unauthorized code
func Unauthorized(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusUnauthorized, CodeUnauthorized, msgFormat, vals...)
}

// AccountNotFound for builds a new Error instance with AccountNotFound code
func AccountNotFound(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusForbidden, CodeAccountNotFound, msgFormat, vals...)
}

// NotReady for builds a new Error instance with NotReady code
func NotReady(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusForbidden, CodeNotReady, msgFormat, vals...)
}

// Conflict for builds a new Error instance with Conflict code
func Conflict(msgFormat string, vals ...interface{}) *Error {
	return New(http.StatusConflict, CodeConflict, msgFormat, vals...)
}

// WithCause adds the cause error
func (e *Error) WithCause(err error) *Error {
	e.Cause = err
	return e
}

// Error implements the standard error interface
func (e *Error) Error() string {
	if e == nil {
		return "nil"
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ManyError identifies many errors from API.
type ManyError struct {
	// HTTPStatus contains the HTTP status code that should be used for this error
	HTTPStatus int `json:"-"`

	// Code identifies the particular error condition [for programatic consumers]
	Code string `json:"code,omitempty"`

	// Message is an textual description of the error
	Message string `json:"message,omitempty"`

	Errors map[string]*Error `json:"errors,omitempty"`
}

func (m *ManyError) Error() string {
	if m == nil {
		return "nil"
	}
	if m.Code != "" {
		return fmt.Sprintf("%s: %s", m.Code, m.Message)
	}

	var errs []string
	for _, e := range m.Errors {
		errs = append(errs, e.Error())
	}

	return strings.Join(errs, ";")
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
	if gErr, ok := err.(*Error); ok {
		m.Errors[key] = gErr
	} else {
		m.Errors[key] = &Error{Code: CodeUnexpected, Message: err.Error(), Cause: err}
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
	_ = codec.NewEncoder(w, encoderHandle(shouldPrettyPrint(r))).Encode(e)
}

// WriteHTTPResponse implements how to serialize this error into a HTTP Response
func (m *ManyError) WriteHTTPResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(m.HTTPStatus)
	_ = codec.NewEncoder(w, encoderHandle(shouldPrettyPrint(r))).Encode(m)
}
