package httperror

import (
	"net/http"

	"google.golang.org/grpc/codes"
)

const (
	// CodeAccountNotFound when requested account not found
	CodeAccountNotFound = "account_not_found"
	// CodeBadNonce is returned for bad nonce.
	CodeBadNonce = "bad_nonce"
	// CodeConflict is returned whith 409 CONFLICT response code.
	CodeConflict = "conflict"
	// CodeConnection is returned when connection failed.
	CodeConnection = "connection"
	// CodeContentLengthRequired is returned when request does not specify ContentLength.
	CodeContentLengthRequired = "content_length_required"
	// CodeFailedToReadRequestBody is returned when there's an error reading the HTTP body of the request.
	CodeFailedToReadRequestBody = "request_body"
	// CodeForbidden is returned when the client is not authorized to access the resource indicated.
	CodeForbidden = "forbidden"
	// CodeInvalidContentType is returned when request specifies invalid Content-Type.
	CodeInvalidContentType = "invalid_content_type"
	// CodeInvalidJSON is returned when we were unable to parse a client supplied JSON Payload.
	CodeInvalidJSON = "invalid_json"
	// CodeInvalidParam is returned where a URL parameter, or other type of generalized parameters value is invalid.
	CodeInvalidParam = "invalid_parameter"
	// CodeInvalidRequest is returned when the request validation failed.
	CodeInvalidRequest = "invalid_request"
	// CodeMalformed is returned when the request was malformed.
	CodeMalformed = "malformed"
	// CodeNotFound is returned when the requested URL doesn't exist.
	CodeNotFound = "not_found"
	// CodeNotReady is returned when the service is not ready to serve
	CodeNotReady = "not_ready"
	// CodeRateLimitExceeded is returned when the client has exceeded their request allotment.
	CodeRateLimitExceeded = "rate_limit_exceeded"
	// CodeRequestFailed is returned when an outbound request failed.
	CodeRequestFailed = "request_failed"
	// CodeRequestTooLarge is returned when the client provided payload is larger than allowed for the particular resource.
	CodeRequestTooLarge = "request_too_large"
	// CodeTimeout is returned when request timed out.
	CodeTimeout = "timeout"
	// CodeTooEarly is returned when the client makes requests too early.
	CodeTooEarly = "too_early"
	// CodeUnauthorized is for unauthorized access.
	CodeUnauthorized = "unauthorized"
	// CodeUnexpected is returned when something went wrong.
	CodeUnexpected = "unexpected"
)

var httpCode = map[int]string{
	http.StatusBadRequest:                   "bad_request",
	http.StatusUnauthorized:                 "unauthorized",
	http.StatusPaymentRequired:              "payment_required",
	http.StatusForbidden:                    "forbidden",
	http.StatusNotFound:                     "not_found",
	http.StatusMethodNotAllowed:             "not_allowed",
	http.StatusNotAcceptable:                "not_acceptable",
	http.StatusProxyAuthRequired:            "auth_required",
	http.StatusRequestTimeout:               "request_timeout",
	http.StatusConflict:                     "conflict",
	http.StatusGone:                         "gone",
	http.StatusLengthRequired:               "length_required",
	http.StatusPreconditionFailed:           "precondition_failed",
	http.StatusRequestEntityTooLarge:        "too_large",
	http.StatusRequestURITooLong:            "uri_too_long",
	http.StatusUnsupportedMediaType:         "unsupported_media_type",
	http.StatusRequestedRangeNotSatisfiable: "bad_request",
	http.StatusExpectationFailed:            "expectation_failed",
	http.StatusTeapot:                       "teapot",
	http.StatusMisdirectedRequest:           "misdirected",
	http.StatusUnprocessableEntity:          "unprocessable",
	http.StatusLocked:                       "locked",
	http.StatusFailedDependency:             "failed_dependency",
	http.StatusTooEarly:                     "too_early",
	http.StatusUpgradeRequired:              "upgrade_required",
	http.StatusPreconditionRequired:         "precondition_required",
	http.StatusTooManyRequests:              "too_many_requests",
	http.StatusRequestHeaderFieldsTooLarge:  "too_large",
	http.StatusUnavailableForLegalReasons:   "legal_reason",

	http.StatusInternalServerError:           CodeUnexpected,
	http.StatusNotImplemented:                "not_implemented",
	http.StatusBadGateway:                    "bad_gateway",
	http.StatusServiceUnavailable:            "unavailable",
	http.StatusGatewayTimeout:                "gateway_timeout",
	http.StatusHTTPVersionNotSupported:       "not_supported",
	http.StatusVariantAlsoNegotiates:         CodeUnexpected,
	http.StatusInsufficientStorage:           "insufficient_storage",
	http.StatusLoopDetected:                  "loop_detected",
	http.StatusNotExtended:                   "not_extended",
	http.StatusNetworkAuthenticationRequired: "authentication_required",
}

// See: https://cloud.google.com/apis/design/errors
var codeStatus = map[codes.Code]int{
	// OK is returned on success.
	codes.OK: http.StatusOK,

	// Canceled indicates the operation was canceled (typically by the caller).
	//
	// The gRPC framework will generate this error code when cancellation
	// is requested.
	codes.Canceled: 499,

	// Unknown error. An example of where this error may be returned is
	// if a Status value received from another address space belongs to
	// an error-space that is not known in this address space. Also
	// errors raised by APIs that do not return enough error information
	// may be converted to this error.
	//
	// The gRPC framework will generate this error code in the above two
	// mentioned cases.
	codes.Unknown: 500,

	// InvalidArgument indicates client specified an invalid argument.
	// Note that this differs from FailedPrecondition. It indicates arguments
	// that are problematic regardless of the state of the system
	// (e.g., a malformed file name).
	//
	// This error code will not be generated by the gRPC framework.
	codes.InvalidArgument: 400,

	// DeadlineExceeded means operation expired before completion.
	// For operations that change the state of the system, this error may be
	// returned even if the operation has completed successfully. For
	// example, a successful response from a server could have been delayed
	// long enough for the deadline to expire.
	//
	// The gRPC framework will generate this error code when the deadline is
	// exceeded.
	codes.DeadlineExceeded: 504,

	// NotFound means some requested entity (e.g., file or directory) was
	// not found.
	//
	// This error code will not be generated by the gRPC framework.
	codes.NotFound: http.StatusNotFound,

	// AlreadyExists means an attempt to create an entity failed because one
	// already exists.
	//
	// This error code will not be generated by the gRPC framework.
	codes.AlreadyExists: http.StatusConflict,

	// PermissionDenied indicates the caller does not have permission to
	// execute the specified operation. It must not be used for rejections
	// caused by exhausting some resource (use ResourceExhausted
	// instead for those errors). It must not be
	// used if the caller cannot be identified (use Unauthenticated
	// instead for those errors).
	//
	// This error code will not be generated by the gRPC core framework,
	// but expect authentication middleware to use it.
	codes.PermissionDenied: 403,

	// ResourceExhausted indicates some resource has been exhausted, perhaps
	// a per-user quota, or perhaps the entire file system is out of space.
	//
	// This error code will be generated by the gRPC framework in
	// out-of-memory and server overload situations, or when a message is
	// larger than the configured maximum size.
	codes.ResourceExhausted: http.StatusTooManyRequests,

	// FailedPrecondition indicates operation was rejected because the
	// system is not in a state required for the operation's execution.
	// For example, directory to be deleted may be non-empty, an rmdir
	// operation is applied to a non-directory, etc.
	//
	// A litmus test that may help a service implementor in deciding
	// between FailedPrecondition, Aborted, and Unavailable:
	//  (a) Use Unavailable if the client can retry just the failing call.
	//  (b) Use Aborted if the client should retry at a higher-level
	//      (e.g., restarting a read-modify-write sequence).
	//  (c) Use FailedPrecondition if the client should not retry until
	//      the system state has been explicitly fixed. E.g., if an "rmdir"
	//      fails because the directory is non-empty, FailedPrecondition
	//      should be returned since the client should not retry unless
	//      they have first fixed up the directory by deleting files from it.
	//  (d) Use FailedPrecondition if the client performs conditional
	//      REST Get/Update/Delete on a resource and the resource on the
	//      server does not match the condition. E.g., conflicting
	//      read-modify-write on the same resource.
	//
	// This error code will not be generated by the gRPC framework.
	codes.FailedPrecondition: http.StatusInternalServerError,

	// Aborted indicates the operation was aborted, typically due to a
	// concurrency issue like sequencer check failures, transaction aborts,
	// etc.
	//
	// See litmus test above for deciding between FailedPrecondition,
	// Aborted, and Unavailable.
	//
	// This error code will not be generated by the gRPC framework.
	codes.Aborted: 409,

	// OutOfRange means operation was attempted past the valid range.
	// E.g., seeking or reading past end of file.
	//
	// Unlike InvalidArgument, this error indicates a problem that may
	// be fixed if the system state changes. For example, a 32-bit file
	// system will generate InvalidArgument if asked to read at an
	// offset that is not in the range [0,2^32-1], but it will generate
	// OutOfRange if asked to read from an offset past the current
	// file size.
	//
	// There is a fair bit of overlap between FailedPrecondition and
	// OutOfRange. We recommend using OutOfRange (the more specific
	// error) when it applies so that callers who are iterating through
	// a space can easily look for an OutOfRange error to detect when
	// they are done.
	//
	// This error code will not be generated by the gRPC framework.
	codes.OutOfRange: 400,

	// Unimplemented indicates operation is not implemented or not
	// supported/enabled in this service.
	//
	// This error code will be generated by the gRPC framework. Most
	// commonly, you will see this error code when a method implementation
	// is missing on the server. It can also be generated for unknown
	// compression algorithms or a disagreement as to whether an RPC should
	// be streaming.
	codes.Unimplemented: 501,

	// Internal errors. Means some invariants expected by underlying
	// system has been broken. If you see one of these errors,
	// something is very broken.
	//
	// This error code will be generated by the gRPC framework in several
	// internal error conditions.
	codes.Internal: 500,

	// Unavailable indicates the service is currently unavailable.
	// This is a most likely a transient condition and may be corrected
	// by retrying with a backoff. Note that it is not always safe to retry
	// non-idempotent operations.
	//
	// See litmus test above for deciding between FailedPrecondition,
	// Aborted, and Unavailable.
	//
	// This error code will be generated by the gRPC framework during
	// abrupt shutdown of a server process or network connection.
	codes.Unavailable: 503,

	// DataLoss indicates unrecoverable data loss or corruption.
	//
	// This error code will not be generated by the gRPC framework.
	codes.DataLoss: 500,

	// Unauthenticated indicates the request does not have valid
	// authentication credentials for the operation.
	//
	// The gRPC framework will generate this error code when the
	// authentication metadata is invalid or a Credentials callback fails,
	// but also expect authentication middleware to generate it.
	codes.Unauthenticated: 401,
}

// HTTPStatusFromRPC returns HTTP status
func HTTPStatusFromRPC(c codes.Code) int {
	return codeStatus[c]
}

var statusCode = map[string]codes.Code{
	CodeAccountNotFound:         codes.NotFound,
	CodeBadNonce:                codes.InvalidArgument,
	CodeConflict:                codes.AlreadyExists,
	CodeConnection:              codes.Unknown,
	CodeContentLengthRequired:   codes.InvalidArgument,
	CodeFailedToReadRequestBody: codes.InvalidArgument,
	CodeForbidden:               codes.PermissionDenied,
	CodeInvalidContentType:      codes.InvalidArgument,
	CodeInvalidJSON:             codes.InvalidArgument,
	CodeInvalidParam:            codes.InvalidArgument,
	CodeInvalidRequest:          codes.InvalidArgument,
	CodeMalformed:               codes.InvalidArgument,
	CodeNotFound:                codes.NotFound,
	CodeNotReady:                codes.Unavailable,
	CodeRateLimitExceeded:       codes.ResourceExhausted,
	CodeRequestFailed:           codes.Unknown,
	CodeRequestTooLarge:         codes.InvalidArgument,
	CodeTooEarly:                codes.ResourceExhausted,
	CodeUnauthorized:            codes.Unauthenticated,
	CodeUnexpected:              codes.Unknown,
}
