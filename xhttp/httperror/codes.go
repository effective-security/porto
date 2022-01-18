package httperror

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
	// CodeTooEarly is returned when the client makes requests too early.
	CodeTooEarly = "too_early"
	// CodeUnauthorized is for unauthorized access.
	CodeUnauthorized = "unauthorized"
	// CodeUnexpected is returned when something went wrong.
	CodeUnexpected = "unexpected"
)
