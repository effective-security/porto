// Package marshal provides helpers to write JSON HTTP responses and to
// decode JSON request bodies, using github.com/ugorji/go/codec.
//
// WriteJSON is the single response path used by porto handlers: it writes
// errors (anything implementing WriteHTTPResponse, such as
// httperror.Error) with their own status code, and everything else as a
// 200 application/json body, gzip-compressed when it is at least 1 KiB and
// the client accepts gzip, and pretty-printed when the URL has a "?pp" query
// parameter. Success responses include Vary: Accept-Encoding.
//
//	func (s *svc) get(w http.ResponseWriter, r *http.Request, _ restserver.Params) {
//		var req ItemRequest
//		if marshal.DecodeBody(w, r, &req) != nil {
//			return // 400 invalid_json already written
//		}
//		item, err := s.store.Get(r.Context(), req.ID)
//		marshal.WriteJSON(w, r, err, item) // first non-nil value wins
//	}
//
// Decoding is strict: unknown JSON fields are an error (DecoderHandle).
package marshal
