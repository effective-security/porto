package telemetry

import (
	"bufio"
	"io"
	"net"
	"net/http"

	"github.com/cockroachdb/errors"
)

// ResponseCapture is a net/http.ResponseWriter that delegates everything to
// the contained delegate, but captures the status code and number of bytes
// written. The status defaults to 200 until WriteHeader is called.
//
// Unwrap exposes the delegate, so http.ResponseController reaches its
// optional features (read and write deadlines, full duplex, flush, hijack).
// ResponseCapture also implements http.Flusher, FlushError and
// http.Hijacker for handlers that assert them directly (WebSocket
// upgrades); they reach the delegate through http.ResponseController. When
// the delegate chain lacks the feature, Flush is a no-op, and FlushError
// and Hijack return an error wrapping http.ErrNotSupported (Hijack does on
// HTTP/2), so asserting http.Hijacker does not prove that hijacking works.
// Status and size cover only what is written through the ResponseCapture,
// not what a handler writes to a hijacked connection. ResponseCapture
// implements io.ReaderFrom, so io.Copy into it (http.ServeContent,
// http.FileServer) keeps the delegate's ReadFrom, which uses sendfile for
// files on plain TCP connections.
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

// Unwrap returns the delegate ResponseWriter; http.ResponseController uses
// it to reach the delegate's optional interfaces.
func (r *ResponseCapture) Unwrap() http.ResponseWriter {
	return r.delegate
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

// ReadFrom copies src to the response, as io.ReaderFrom, and counts the
// bytes copied. It calls the delegate's ReadFrom when the delegate
// implements io.ReaderFrom, and copies through its Write otherwise; like
// Write, it returns the delegate's error as is.
func (r *ResponseCapture) ReadFrom(src io.Reader) (int64, error) {
	var n int64
	var err error
	if rf, ok := r.delegate.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(src)
	} else {
		n, err = io.Copy(r.delegate, src)
	}
	r.bodySize += uint64(n)
	return n, err
}

// WriteHeader sets the HTTP status code of the response
func (r *ResponseCapture) WriteHeader(sc int) {
	r.statusCode = sc
	r.delegate.WriteHeader(sc)
}

// Flush sends any buffered data to the client when the delegate chain
// supports flushing. It implements http.Flusher, which cannot report
// errors, so a failed or unsupported flush is ignored; use FlushError, or
// http.ResponseController.Flush, which calls it, to see the error.
func (r *ResponseCapture) Flush() {
	_ = r.FlushError()
}

// FlushError flushes like Flush and returns the delegate chain's error: an
// error wrapping http.ErrNotSupported when no writer in the chain can
// flush, or the write error after the client went away.
// http.ResponseController.Flush calls it, so streaming handlers see the
// error through the ResponseCapture.
func (r *ResponseCapture) FlushError() error {
	if err := http.NewResponseController(r.delegate).Flush(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// Hijack lets the caller take over the connection, as http.Hijacker, when
// the delegate chain supports it (HTTP/1.x). Otherwise, for example on
// HTTP/2, it returns an error wrapping http.ErrNotSupported.
func (r *ResponseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(r.delegate).Hijack()
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	return conn, rw, nil
}
