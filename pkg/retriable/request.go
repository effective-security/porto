package retriable

import (
	"io"
	"net/http"

	"github.com/cockroachdb/errors"
)

// lenReader is an interface implemented by many in-memory io.Reader's. Used
// for automatically sending the right Content-Length header when possible.
type lenReader interface {
	Len() int
}

// Requestor is the minimal interface for sending an HTTP request,
// satisfied by *Client and *http.Client.
type Requestor interface {
	// Do sends the request and returns the response; the caller must close
	// the response body.
	Do(r *http.Request) (*http.Response, error)
}

// ReaderFunc returns a fresh reader over the request body; it is called
// before every attempt so the body can be re-sent on retry.
type ReaderFunc func() (io.Reader, error)

// Request is an *http.Request whose body can be rewound between retries.
// It is produced by NewRequest and used internally by Client.Do.
type Request struct {
	// body is a seekable reader over the request body payload. This is
	// used to rewind the request data in between retries.
	body ReaderFunc

	// Embed an HTTP request directly. This makes a *Request act exactly
	// like an *http.Request so that all meta methods are supported.
	*http.Request
}

// NewRequest creates a Request whose body is rewound (Seek to 0) for each
// attempt. Content-Length is set when rawBody exposes Len()
// (bytes.Reader, strings.Reader). The request has no context; set one with
// WithContext before sending.
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

// WithHeaders appends the given headers to the request (Header.Add).
func (r *Request) WithHeaders(headers map[string]string) *Request {
	for header, val := range headers {
		r.Header.Add(header, val)
	}

	return r
}

// AddHeader appends a header value to the request (Header.Add).
func (r *Request) AddHeader(header, value string) *Request {
	r.Header.Add(header, value)
	return r
}
