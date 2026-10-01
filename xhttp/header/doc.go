// Package header defines constants for HTTP header names and common
// Content-Type values used across porto (X-Correlation-ID, Authorization,
// application/json, application/grpc-web+proto, ...). Header names are in
// canonical MIME form and can be passed directly to http.Header methods,
// except Authority, the HTTP/2 pseudo-header used in gRPC metadata.
package header
