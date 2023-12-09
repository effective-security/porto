package retriable

import (
	"io"
	"net/http"

	"github.com/pkg/errors"
)

// lenReader is an interface implemented by many in-memory io.Reader's. Used
// for automatically sending the right Content-Length header when possible.
type lenReader interface {
	Len() int
}

// Requestor defines interface to make HTTP calls
type Requestor interface {
	Do(r *http.Request) (*http.Response, error)
}

// ReaderFunc is the type of function that can be given natively to NewRequest
type ReaderFunc func() (io.Reader, error)

// Request wraps the metadata needed to create HTTP requests.
type Request struct {
	// body is a seekable reader over the request body payload. This is
	// used to rewind the request data in between retries.
	body ReaderFunc

	// Embed an HTTP request directly. This makes a *Request act exactly
	// like an *http.Request so that all meta methods are supported.
	*http.Request
}

// NewRequest creates a new wrapped request.
func NewRequest(method, url string, rawBody io.ReadSeeker) (*Request, error) {
	var body ReaderFunc
	var contentLength int64

	if rawBody != nil {
		body = func() (io.Reader, error) {
			_, _ = rawBody.Seek(0, 0)
			return io.NopCloser(rawBody), nil
		}
		if lr, ok := rawBody.(lenReader); ok {
			contentLength = int64(lr.Len())
		}
	}

	httpReq, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	httpReq.ContentLength = contentLength

	return &Request{body: body, Request: httpReq}, nil
}

// WithHeaders adds additional headers to the request
func (r *Request) WithHeaders(headers map[string]string) *Request {
	for header, val := range headers {
		r.Request.Header.Add(header, val)
	}

	return r
}

// AddHeader adds additional header to the request
func (r *Request) AddHeader(header, value string) *Request {
	r.Request.Header.Add(header, value)
	return r
}
