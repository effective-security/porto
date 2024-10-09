package httperror

import (
	"context"
	"fmt"
	"net/http"

	"github.com/effective-security/porto/xhttp/correlation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	anypb "google.golang.org/protobuf/types/known/anypb"
)

// NewGrpcFromCtx returns new GRPC error
func NewGrpcFromCtx(ctx context.Context, code codes.Code, msgFormat string, vals ...interface{}) *Error {
	hs := codeStatus[code]
	e := &Error{
		HTTPStatus: hs,
		RPCStatus:  code,
		Code:       httpCode[hs],
		Message:    fmt.Sprintf(msgFormat, vals...),
	}

	if v := correlation.Value(ctx); v != nil {
		e.RequestID = v.ID
	}

	return e
}

// NewGrpc returns new GRPC error
func NewGrpc(code codes.Code, msgFormat string, vals ...interface{}) *Error {
	hs := codeStatus[code]
	e := &Error{
		HTTPStatus: hs,
		RPCStatus:  code,
		Code:       httpCode[hs],
		Message:    fmt.Sprintf(msgFormat, vals...),
	}

	return e
}

// NewFromPb returns Error instance, from gRPC error
func NewFromPb(err error) *Error {
	if e, ok := err.(*Error); ok {
		return e
	}
	if st, ok := status.FromError(err); ok {
		code := st.Code()
		hs := HTTPStatusFromRPC(code)
		return &Error{
			HTTPStatus: hs,
			RPCStatus:  code,
			Code:       httpCode[hs],
			Message:    st.Message(),
			RequestID:  CorrelationID(err),
		}
	}

	return New(http.StatusInternalServerError, CodeUnexpected, "%s", err.Error()).WithCause(err)
}

// GRPCStatus returns gRPC status
func (e *Error) GRPCStatus() *status.Status {
	st := status.New(e.RPCStatus, e.Message)
	if e.RequestID != "" {
		cid := correlationInfo{
			anypb.Any{
				TypeUrl: "@correlation.id",
				Value:   []byte(e.RequestID),
			},
		}

		st, _ = st.WithDetails(&cid)
	}
	return st
}

// CorrelationID returns correlation ID from GRPC error
func CorrelationID(err error) string {
	if tse, ok := err.(*Error); ok {
		return tse.CorrelationID()
	}

	if s, ok := status.FromError(err); ok {
		for _, d := range s.Details() {
			switch val := d.(type) {
			case *anypb.Any:
				if val.TypeUrl == "@correlation.id" {
					return string(val.Value)
				}
			case *correlationInfo:
				return string(val.Value)
			}
		}
	}
	return ""
}

type correlationInfo struct {
	anypb.Any
}

// GRPCMessage returns gRPC error description
func GRPCMessage(err error) string {
	if s, ok := status.FromError(err); ok {
		return s.Message()
	}
	return err.Error()
}

// GRPCCode returns gRPC error code
func GRPCCode(err error) codes.Code {
	if s, ok := status.FromError(err); ok {
		return s.Code()
	}
	return codes.Internal
}
