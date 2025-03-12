package header

const (
	// Accept is HTTP header for "Accept"
	Accept = "Accept"
	// AcceptEncoding is HTTP header for "Accept-Encoding"
	AcceptEncoding = "Accept-Encoding"
	// ApplicationJSON is HTTP header value for "application/json"
	ApplicationJSON = "application/json"
	// ApplicationJoseJSON is HTTP header value for "application/jose+json"
	ApplicationJoseJSON = "application/jose+json"
	// ApplicationGRPC is HTTP header value for "application/grpc"
	ApplicationGRPC = "application/grpc"
	// ApplicationGRPCWebProto is HTTP header value for "application/grpc-web+proto"
	ApplicationGRPCWebProto = "application/grpc-web+proto"
	// ApplicationGRPCWebText is HTTP header value for "application/grpc-web-text"
	ApplicationGRPCWebText = "application/grpc-web-text"
	// ApplicationTimestampQuery is HTTP header value for RFC3161 Timestamp request
	ApplicationTimestampQuery = "application/timestamp-query"
	// ApplicationTimestampReply is HTTP header value for RFC3161 Timestamp response
	ApplicationTimestampReply = "application/timestamp-reply"
	// Authorization is HTTP header for "Authorization"
	Authorization = "Authorization"
	// Bearer is token type for "Authorization" header
	Bearer = "Bearer"
	// DPoP is token type for "Authorization" header,
	// and header name for DPoP
	DPoP = "DPoP"
	// CacheControl is HTTP header for "Cache-Control"
	CacheControl = "Cache-Control"
	// ContentDisposition is HTTP header for "Content-Disposition"
	ContentDisposition = "Content-Disposition"
	// ContentEncoding is HTTP header for "Content-Encoding"
	ContentEncoding = "Content-Encoding"
	// ContentLength is HTTP header for "Content-Length"
	ContentLength = "Content-Length"
	// ContentType is HTTP header for "Content-Type"
	ContentType = "Content-Type"
	// Gzip content type for "gzip"
	Gzip = "gzip"
	// IfMatch is HTTP header for "If-Match"
	IfMatch = "If-Match"
	// Link is HTTP header for "Link"
	Link = "Link"
	// Location is HTTP header for "Location"
	Location = "Location"
	// ReplayNonce is HTTP header for "Replay-Nonce"
	ReplayNonce = "Replay-Nonce"
	// TextPlain is HTTP header value for "application/json"
	TextPlain = "text/plain"
	// UserAgent is HTTP header value for "User-Agent"
	UserAgent = "User-Agent"
	// XHostname contains the name of the HTTP header to indicate which host requested the signature
	XHostname = "X-HostName"
	// XCorrelationID is HTTP header for "X-Correlation-ID"
	XCorrelationID = "X-Correlation-ID"
	// XDeviceID is HTTP header for "X-Device-ID"
	XDeviceID = "X-Device-ID"
	// XFilename contains the name of the artifact to sign
	XFilename = "X-Filename"
	// XForwardedProto contains the protocol
	XForwardedProto = "X-Forwarded-Proto"
)
