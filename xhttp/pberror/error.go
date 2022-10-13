package pberror

import (
	"fmt"

	"github.com/effective-security/porto/xhttp/correlation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// server-side error
var (
	ErrGRPCTimeout          = status.New(codes.Unavailable, "request timed out").Err()
	ErrGRPCPermissionDenied = status.New(codes.PermissionDenied, "permission denied").Err()
	ErrGRPCInvalidArgument  = status.New(codes.InvalidArgument, "invalid argument").Err()

	errStringToError = map[string]error{
		ErrorDesc(ErrGRPCTimeout):          ErrGRPCTimeout,
		ErrorDesc(ErrGRPCPermissionDenied): ErrGRPCPermissionDenied,
		ErrorDesc(ErrGRPCInvalidArgument):  ErrGRPCInvalidArgument,
	}
)

// client-side error
var (
	ErrTimeout          = Error(ErrGRPCTimeout)
	ErrPermissionDenied = Error(ErrGRPCPermissionDenied)
	ErrInvalidArgument  = Error(ErrGRPCInvalidArgument)
)

// GRPCError defines gRPC server errors.
type GRPCError struct {
	requestID string
	code      codes.Code
	desc      string
}

// RequestID returns request ID
func (e GRPCError) RequestID() string {
	return e.requestID
}

// Code returns grpc/codes.Code.
func (e GRPCError) Code() codes.Code {
	return e.code
}

// GRPCStatus interface implementation
func (e GRPCError) GRPCStatus() *status.Status {
	return status.New(e.code, e.desc)
}

func (e GRPCError) Error() string {
	return e.desc
}

// Error returns GRPCError
func Error(err error) error {
	if err == nil {
		return nil
	}
	verr, ok := errStringToError[ErrorDesc(err)]
	if !ok {
		// not gRPC error
		return err
	}
	ev, ok := status.FromError(verr)
	var desc string
	if ok {
		desc = ev.Message()
	} else {
		desc = verr.Error()
	}

	e := GRPCError{code: ev.Code(), desc: desc}
	if ctx, ok := err.(correlation.Correlation); ok {
		e.requestID = ctx.CorrelationID()
	}

	return e
}

// ErrorDesc returns error description
func ErrorDesc(err error) string {
	if s, ok := status.FromError(err); ok {
		return s.Message()
	}
	return err.Error()
}

// NewError returns new GRPCError
func NewError(code codes.Code, msgFormat string, vals ...interface{}) error {
	return GRPCError{
		code: code,
		desc: fmt.Sprintf(msgFormat, vals...),
	}
}
