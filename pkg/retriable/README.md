# retriable

Rich HTTP client

## Generic HTTP features

The package provides generic interface to send HTTP requests, and decode responses.

```go
// GenericHTTP defines a number of generalized HTTP request handling wrappers
type GenericHTTP interface {
	// Request sends request to the specified hosts.
	// The supplied hosts are tried in order until one succeeds.
	// It will decode the response payload into the supplied body parameter.
	// It returns the HTTP headers, status code, and an optional error.
	// For responses with status codes >= 300 it will try and convert the response
	// into a Go error.
	// If configured, this call will apply retry logic.
	//
	// hosts should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
	// path should be an absolute URI path, i.e. /foo/bar/baz
	// requestBody can be io.Reader, []byte, or an object to be JSON encoded
	// responseBody can be io.Writer, or a struct to decode JSON into.
	Request(ctx context.Context, method string, hosts []string, path string, requestBody interface{}, responseBody interface{}) (http.Header, int, error)

	// RequestURL is similar to Request but uses raw URL to one host
	RequestURL(ctx context.Context, method, rawURL string, requestBody interface{}, responseBody interface{}) (http.Header, int, error)

	// HeadTo makes HEAD request against the specified hosts.
	// The supplied hosts are tried in order until one succeeds.
	//
	// hosts should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
	// path should be an absolute URI path, i.e. /foo/bar/baz
	HeadTo(ctx context.Context, hosts []string, path string) (http.Header, int, error)
}
```
