package httperror

import (
	"context"
	"fmt"
	"net/http"

	"github.com/effective-security/porto/xhttp/correlation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"
	anypb "google.golang.org/protobuf/types/known/anypb"
)

// Type URLs of the status details attached by GRPCStatus.
const (
	correlationIDTypeURL = "@correlation.id"
	errorCodeTypeURL     = "@httperror.code"
)

// restoredHTTPStatus lists codes whose HTTP status cannot be derived from
// their gRPC code; NewFromPb, Wrap and Status restore it from the code
// detail attached by GRPCStatus.
var restoredHTTPStatus = map[string]int{
	// ResourceExhausted alone maps to 429, which invites a retry.
	CodeRequestTooLarge: http.StatusRequestEntityTooLarge,
}

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
// correlation ID detail, see CorrelationID, and restoring HTTP 413
// request_too_large from the code detail), anything else becomes a 500
// unexpected error with the original as cause.
func NewFromPb(err error) *Error {
	if e, ok := err.(*Error); ok {
		return e
	}
	if st, ok := status.FromError(err); ok {
		hs, code := statusHTTP(st)
		return &Error{
			HTTPStatus: hs,
			RPCStatus:  st.Code(),
			Code:       code,
			Message:    st.Message(),
			RequestID:  CorrelationID(err),
		}
	}

	return New(http.StatusInternalServerError, CodeUnexpected, "%s", err.Error()).WithCause(err)
}

// GRPCStatus returns the gRPC status for the error (RPCStatus and Message),
// attaching the Code and RequestID as details so NewFromPb and CorrelationID
// can recover them on the client side. It makes *Error usable as a gRPC
// handler return value.
func (e *Error) GRPCStatus() *status.Status {
	return newStatus(e.RPCStatus, e.Message, e.Code, e.RequestID)
}

// newStatus builds a gRPC status carrying the httperror code and the
// correlation ID as details. A status with code OK cannot carry details and
// is returned without them.
func newStatus(rpc codes.Code, message, code, requestID string) *status.Status {
	st := status.New(rpc, message)
	if rpc == codes.OK {
		return st
	}
	var details []protoadapt.MessageV1
	if code != "" {
		details = append(details, newDetail(errorCodeTypeURL, code))
	}
	if requestID != "" {
		details = append(details, newDetail(correlationIDTypeURL, requestID))
	}
	if len(details) == 0 {
		return st
	}
	if withDetails, err := st.WithDetails(details...); err == nil {
		st = withDetails
	}
	return st
}

// statusHTTP returns the HTTP status and httperror code for a gRPC status:
// the Google API mapping of its code, unless the code detail names a code
// in restoredHTTPStatus that maps to the same gRPC code.
func statusHTTP(st *status.Status) (int, string) {
	code := st.Code()
	if errCode := detailValue(st, errorCodeTypeURL); errCode != "" {
		if hs, ok := restoredHTTPStatus[errCode]; ok && statusCode[errCode] == code {
			return hs, errCode
		}
	}
	hs := codeStatus[code]
	return hs, httpCode[hs]
}

// CorrelationID extracts the correlation ID from an *Error or from the
// detail attached by Error.GRPCStatus to a gRPC status error; "" if none.
func CorrelationID(err error) string {
	if tse, ok := err.(*Error); ok {
		return tse.CorrelationID()
	}

	if s, ok := status.FromError(err); ok {
		return detailValue(s, correlationIDTypeURL)
	}
	return ""
}

// detailValue returns the value of the first string detail with typeURL.
func detailValue(st *status.Status, typeURL string) string {
	for _, d := range st.Details() {
		switch val := d.(type) {
		case *anypb.Any:
			if val.TypeUrl == typeURL {
				return string(val.Value)
			}
		case *stringDetail:
			if val.TypeUrl == typeURL {
				return string(val.Value)
			}
		}
	}
	return ""
}

// stringDetail is a status detail holding a string under a private type URL.
type stringDetail struct {
	anypb.Any
}

func newDetail(typeURL, value string) *stringDetail {
	return &stringDetail{
		anypb.Any{
			TypeUrl: typeURL,
			Value:   []byte(value),
		},
	}
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
