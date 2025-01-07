package httperror

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/ugorji/go/codec"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ManyError identifies many errors from API.
type ManyError struct {
	// HTTPStatus contains the HTTP status code that should be used for this error
	HTTPStatus int `json:"-"`

	RPCStatus codes.Code `json:"-"`

	// Code identifies the particular error condition [for programatic consumers]
	Code string `json:"code,omitempty"`

	// RequestID identifies the request ID
	RequestID string `json:"request_id,omitempty"`

	// Message is an textual description of the error
	Message string `json:"message,omitempty"`

	Errors map[string]*Error `json:"errors,omitempty"`

	// Cause is the first original error
	cause error `json:"-"`

	lock sync.Mutex `json:"-"`
}

// GRPCStatus returns gRPC status
func (m *ManyError) GRPCStatus() *status.Status {
	return status.New(statusCode[m.Code], m.Message)
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

// WithCause adds the cause error
func (m *ManyError) WithCause(err error) *ManyError {
	m.cause = err
	return m
}

// NewMany builds new ManyError instance, build message string along the way
func NewMany(status int, code string, msgFormat string, vals ...interface{}) *ManyError {
	return &ManyError{
		HTTPStatus: status,
		RPCStatus:  statusCode[code],
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

	m.lock.Lock()
	defer m.lock.Unlock()

	if m.Errors == nil {
		m.Errors = make(map[string]*Error)
	}
	if m.cause == nil {
		m.cause = err
	}
	if gErr, ok := err.(*Error); ok {
		m.Errors[key] = gErr
	} else {
		m.Errors[key] = &Error{
			Code:    CodeUnexpected,
			Message: err.Error(),
			cause:   err,
		}
	}
	return m
}

// HasErrors check if ManyError has any nested error associated with it.
func (m *ManyError) HasErrors() bool {
	return len(m.Errors) > 0
}

// WriteHTTPResponse implements how to serialize this error into a HTTP Response
func (m *ManyError) WriteHTTPResponse(w http.ResponseWriter, r *http.Request) {
	// TODO: check r.Accept
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(m.HTTPStatus)
	if m.RequestID == "" {
		m.RequestID = correlation.ID(r.Context())
	}
	_ = codec.NewEncoder(w, encoderHandle(shouldPrettyPrint(r))).Encode(m)
}
