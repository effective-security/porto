package telemetry

import (
	"net/http"
)

// ResponseCapture is a net/http.ResponseWriter that delegates everything
// to the contained delegate, but captures the status code and number of bytes written
type ResponseCapture struct {
	statusCode int
	bodySize   uint64
	delegate   http.ResponseWriter
}

// NewResponseCapture returns a new ResponseCapture instance that delegates writes to the supplied ResponseWriter
func NewResponseCapture(w http.ResponseWriter) *ResponseCapture {
	return &ResponseCapture{http.StatusOK, 0, w}
}

// StatusCode returns the http status set by the handler.
func (r *ResponseCapture) StatusCode() int {
	return r.statusCode
}

// BodySize returns in bytes the total number of bytes written to the response body so far.
func (r *ResponseCapture) BodySize() uint64 {
	return r.bodySize
}

//
// http.ResponseWriter inteface methods
//

// Header returns the underlying writers Header instance
func (r *ResponseCapture) Header() http.Header {
	return r.delegate.Header()
}

// Write the supplied data to the response (tracking the number of bytes written as we go)
func (r *ResponseCapture) Write(data []byte) (int, error) {
	r.bodySize += uint64(len(data))
	return r.delegate.Write(data)
}

// WriteHeader sets the HTTP status code of the response
func (r *ResponseCapture) WriteHeader(sc int) {
	r.statusCode = sc
	r.delegate.WriteHeader(sc)
}

// Flush sends any buffered data to the client.
func (r *ResponseCapture) Flush() {
	if flusher, ok := r.delegate.(http.Flusher); ok {
		flusher.Flush()
	}
}
