// Package streamctx wraps a grpc.ServerStream so that its Context returns a
// replacement context. Stream interceptors use it to attach values (identity,
// correlation ID) to the context seen by the handler:
//
//	func interceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
//		ctx := context.WithValue(ss.Context(), key, value)
//		return handler(srv, streamctx.WithContext(ctx, ss))
//	}
package streamctx
