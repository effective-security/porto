// Package httperror defines structured API errors that carry an HTTP status,
// a machine-readable code, a gRPC status code and the request correlation ID,
// and that know how to serialise themselves as a JSON HTTP response.
//
// Error and ManyError implement error, marshal.WriteHTTPResponse and
// GRPCStatus(), so a single value can be returned from a handler, written
// with marshal.WriteJSON, or returned from a gRPC method:
//
//	if id == "" {
//		return httperror.InvalidParam("id is required").WithContext(ctx)
//	}
//	item, err := db.Get(ctx, id)
//	if err != nil {
//		return httperror.WrapWithCtx(ctx, err, "failed to load item %s", id) // maps to 404/408/500
//	}
//
// The JSON wire format is {"code": "...", "message": "...", "request_id": "..."};
// ManyError adds an "errors" map keyed by field or item.
//
// Code* constants list the well-known codes. HTTPStatusFromRPC, NewGrpc,
// NewFromPb and Status convert between gRPC codes and HTTP statuses using
// the Google API error mapping (note: PermissionDenied maps to 401).
package httperror
