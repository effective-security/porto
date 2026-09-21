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

// NewGrpcFromCtx returns an *Error for the gRPC code with the HTTP status
// and Code derived from it, and RequestID taken from ctx.
func NewGrpcFromCtx(ctx context.Context, code codes.Code, msgFormat string, vals ...any) *Error {
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

// NewGrpc returns an *Error for the gRPC code, with HTTPStatus and Code
// derived from it via HTTPStatusFromRPC.
func NewGrpc(code codes.Code, msgFormat string, vals ...any) *Error {
	hs := codeStatus[code]
	e := &Error{
		HTTPStatus: hs,
		RPCStatus:  code,
		Code:       httpCode[hs],
		Message:    fmt.Sprintf(msgFormat, vals...),
	}

	return e
}

// NewFromPb converts an error received from a gRPC call into an *Error:
// an *Error is returned as is, a status error is mapped by code (keeping the
// correlation ID detail, see CorrelationID), anything else becomes a 500
// unexpected error with the original as cause.
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

// GRPCStatus returns the gRPC status for the error (RPCStatus and Message),
// attaching the RequestID as a detail so CorrelationID can recover it on the
// client side. It makes *Error usable as a gRPC handler return value.
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

// CorrelationID extracts the correlation ID from an *Error or from the
// detail attached by Error.GRPCStatus to a gRPC status error; "" if none.
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

// GRPCMessage returns the status message of a gRPC error, or err.Error()
// for other errors.
func GRPCMessage(err error) string {
	if s, ok := status.FromError(err); ok {
		return s.Message()
	}
	return err.Error()
}

// GRPCCode returns the status code of a gRPC error, or codes.Internal for
// errors that carry no status.
func GRPCCode(err error) codes.Code {
	if s, ok := status.FromError(err); ok {
		return s.Code()
	}
	return codes.Internal
}
