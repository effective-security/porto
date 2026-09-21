package retriable

import (
	"context"
	"net/http"
)

// HeadTo makes a HEAD request against the specified host, applying the
// retry Policy and RequestTimeout, and returns the response headers and
// status code. Unlike Request, a non-2xx status is not turned into an error.
//
// host should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) HeadTo(ctx context.Context, host string, path string) (http.Header, int, error) {
	resp, err := c.executeRequest(ctx, http.MethodHead, host, path, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	return resp.Header, resp.StatusCode, nil
}

// Head makes a HEAD request to the configured host (see HeadTo).
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Head(ctx context.Context, path string) (http.Header, int, error) {
	return c.HeadTo(ctx, c.host, path)
}

// Post makes an HTTP POST to the configured host (see Request).
// requestBody is sent as-is for io.Reader, []byte and string, otherwise JSON
// encoded; the response is decoded into responseBody and statuses >= 300
// are returned as an error, with retries applied per the client Policy.
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Post(ctx context.Context, path string, requestBody any, responseBody any) (http.Header, int, error) {
	return c.Request(ctx, "POST", c.host, path, requestBody, responseBody)
}

// Put makes an HTTP PUT to the configured host (see Request).
// requestBody is sent as-is for io.Reader, []byte and string, otherwise JSON
// encoded; the response is decoded into responseBody and statuses >= 300
// are returned as an error, with retries applied per the client Policy.
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Put(ctx context.Context, path string, requestBody any, responseBody any) (http.Header, int, error) {
	return c.Request(ctx, "PUT", c.host, path, requestBody, responseBody)
}

// Get makes an HTTP GET to the configured host (see Request) and decodes
// the response into body (io.Writer or JSON target). Statuses >= 300 are
// returned as an error, with retries applied per the client Policy.
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Get(ctx context.Context, path string, body any) (http.Header, int, error) {
	return c.Request(ctx, "GET", c.host, path, nil, body)
}

// Delete makes an HTTP DELETE to the configured host (see Request) and
// decodes the response into body (io.Writer or JSON target). Statuses >= 300
// are returned as an error, with retries applied per the client Policy.
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Delete(ctx context.Context, path string, body any) (http.Header, int, error) {
	return c.Request(ctx, "DELETE", c.host, path, nil, body)
}
