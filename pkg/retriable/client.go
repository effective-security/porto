package retriable

import (
	"context"
	"net/http"
)

// HeadTo makes HEAD request against the specified hosts.
// The supplied hosts are tried in order until one succeeds.
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

// Head makes HEAD request.
// path should be an absolute URI path, i.e. /foo/bar/baz
// The client must be configured with the hosts list.
func (c *Client) Head(ctx context.Context, path string) (http.Header, int, error) {
	return c.HeadTo(ctx, c.host, path)
}

// Post makes an HTTP POST to the supplied path.
// The HTTP response will be decoded into reponseBody, and the status
// code (and potentially an error) returned. It'll try and map errors (statusCode >= 300)
// into a go error, waits & retries for rate limiting errors will be applied based on the
// client config.
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Post(ctx context.Context, path string, requestBody interface{}, responseBody interface{}) (http.Header, int, error) {
	return c.Request(ctx, "POST", c.host, path, requestBody, responseBody)
}

// Put makes an HTTP PUT to the supplied path.
// The HTTP response will be decoded into reponseBody, and the status
// code (and potentially an error) returned. It'll try and map errors (statusCode >= 300)
// into a go error, waits & retries for rate limiting errors will be applied based on the
// client config.
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Put(ctx context.Context, path string, requestBody interface{}, responseBody interface{}) (http.Header, int, error) {
	return c.Request(ctx, "PUT", c.host, path, requestBody, responseBody)
}

// PostTo is the same as Post, but to the specified host. [the supplied hosts are
// tried in order until one succeeds, or we run out]
// each host should include all the protocol/host/port preamble, e.g. http://foo.bar:3444
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) PostTo(ctx context.Context, hosts []string, path string, requestBody interface{}, responseBody interface{}) (http.Header, int, error) {
	return c.Request(ctx, "POST", c.host, path, requestBody, responseBody)
}

// Get fetches the supplied resource using the current selected cluster member
// [typically the leader], it will decode the response payload into the supplied
// body parameter. it returns the HTTP status code, and an optional error
// for responses with status codes >= 300 it will try and convert the response
// into an go error.
// If configured, this call will wait & retry on rate limit and leader election errors
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Get(ctx context.Context, path string, body interface{}) (http.Header, int, error) {
	return c.Request(ctx, "GET", c.host, path, nil, body)
}

// Delete removes the supplied resource using the current selected cluster member
// [typically the leader], it will decode the response payload into the supplied
// body parameter. it returns the HTTP status code, and an optional error
// for responses with status codes >= 300 it will try and convert the response
// into an go error.
// If configured, this call will wait & retry on rate limit and leader election errors
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Delete(ctx context.Context, path string, body interface{}) (http.Header, int, error) {
	return c.Request(ctx, "DELETE", c.host, path, nil, body)
}
