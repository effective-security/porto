package pberror

import (
	"context"
	"fmt"

	"github.com/effective-security/porto/xhttp/correlation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	anypb "google.golang.org/protobuf/types/known/anypb"
)

// grpc error
var (
	ErrGRPCTimeout          = status.New(codes.Unavailable, "request timed out").Err()
	ErrGRPCPermissionDenied = status.New(codes.PermissionDenied, "permission denied").Err()
	ErrGRPCInvalidArgument  = status.New(codes.InvalidArgument, "invalid argument").Err()
)

// New returns new GRPC error
func New(code codes.Code, msgFormat string, vals ...interface{}) error {
	return status.New(code, fmt.Sprintf(msgFormat, vals...)).Err()
}

// NewFromCtx returns new GRPC error
func NewFromCtx(ctx context.Context, code codes.Code, msgFormat string, vals ...interface{}) error {
	e := status.New(code, fmt.Sprintf(msgFormat, vals...))

	if v := correlation.Value(ctx); v != nil {
		cid := correlationInfo{
			anypb.Any{
				TypeUrl: "@correlation.id",
				Value:   []byte(v.ID),
			},
		}

		e, _ = e.WithDetails(&cid)
	}

	return e.Err()
}

type correlationInfo struct {
	anypb.Any
}

// Message returns gRPC error description
func Message(err error) string {
	if s, ok := status.FromError(err); ok {
		return s.Message()
	}
	return err.Error()
}

// Error returns error message
func Error(err error) string {
	cid := CorrelationID(err)
	msg := Message(err)
	if cid != "" {
		return fmt.Sprintf("request %s: %s", cid, msg)
	}
	return msg
}

// Code returns gRPC error code
func Code(err error) codes.Code {
	if s, ok := status.FromError(err); ok {
		return s.Code()
	}
	return codes.Internal
}

// CorrelationID returns correlation ID from GRPC error
func CorrelationID(err error) string {
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
