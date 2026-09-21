// Package correlation propagates a per-request correlation ID through
// http.Request contexts, gRPC metadata and log entries.
//
// An ID is taken from the incoming X-Correlation-ID or X-Request-ID header
// (gRPC: x-correlation-id / x-request-id metadata), truncated to IDSize
// characters, or generated randomly when absent. The ID is stored in the
// context (see ID, Value), attached to xlog context fields as "ctx", and
// echoed back in the X-Correlation-ID response header.
//
//	h := correlation.NewHandler(next)                 // HTTP middleware
//	srv := grpc.NewServer(grpc.UnaryInterceptor(correlation.NewAuthUnaryInterceptor()))
//
//	id := correlation.ID(ctx)                          // read it later
//	ctx = correlation.WithMetaFromContext(ctx)         // outgoing gRPC call
//
// Both gRPC interceptors also recover panics from downstream handlers,
// log them with a stack trace and return a generic "unhandled exception"
// error.
package correlation
