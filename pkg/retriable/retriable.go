package retriable

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/effective-security/porto/x/slices"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "retriable")

const (
	// Success returned when request succeeded
	Success = "success"
	// NotFound returned when request returned 404
	NotFound = "not-found"
	// LimitExceeded returned when retry limit exceeded
	LimitExceeded = "limit-exceeded"
	// DeadlineExceeded returned when request was timed out
	DeadlineExceeded = "deadline"
	// Cancelled returned when request was cancelled
	Cancelled = "cancelled"
	// NonRetriableError returned when non-retriable error occured
	NonRetriableError = "non-retriable"
)

// contextValueName is cusmom type to be used as a key in context values map
type contextValueName string

const (
	// ContextValueForHTTPHeader specifies context value name for HTTP headers
	contextValueForHTTPHeader = contextValueName("HTTP-Header")
)

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

	// Head makes HEAD request against the specified hosts.
	// The supplied hosts are tried in order until one succeeds.
	//
	// hosts should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
	// path should be an absolute URI path, i.e. /foo/bar/baz
	Head(ctx context.Context, hosts []string, path string) (http.Header, int, error)
}

// ShouldRetry specifies a policy for handling retries. It is called
// following each request with the response, error values returned by
// the http.Client and the number of already made retries.
// If ShouldRetry returns false, the Client stops retrying
// and returns the response to the caller. The
// Client will close any response body when retrying, but if the retriable is
// aborted it is up to the caller to properly close any response body before returning.
type ShouldRetry func(r *http.Request, resp *http.Response, err error, retries int) (bool, time.Duration, string)

// Policy represents the retriable policy
type Policy struct {

	// Retries specifies a map of HTTP Status code to ShouldRetry function,
	// 0 status code indicates a connection related error (network, TLS, DNS etc.)
	Retries map[int]ShouldRetry

	// Maximum number of retries.
	TotalRetryLimit int

	RequestTimeout time.Duration
}

// A ClientOption modifies the default behavior of Client.
type ClientOption interface {
	applyOption(*Client)
}

type optionFunc func(*Client)

func (f optionFunc) applyOption(opts *Client) { f(opts) }

type clientOptions struct {
}

// WithName is a ClientOption that specifies client's name for logging purposes.
//
//   retriable.New(retriable.WithName("tlsclient"))
//
// This option cannot be provided for constructors which produce result
// objects.
func WithName(name string) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithName(name)
	})
}

// WithPolicy is a ClientOption that specifies retriable policy.
//
//   retriable.New(retriable.WithPolicy(p))
//
// This option cannot be provided for constructors which produce result
// objects.
func WithPolicy(policy *Policy) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithPolicy(policy)
	})
}

// WithTLS is a ClientOption that specifies TLS configuration.
//
//   retriable.New(retriable.WithTLS(t))
//
// This option cannot be provided for constructors which produce result
// objects.
func WithTLS(tlsConfig *tls.Config) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithTLS(tlsConfig)
	})
}

// WithTransport is a ClientOption that specifies HTTP Transport configuration.
//
//   retriable.New(retriable.WithTransport(t))
//
// This option cannot be provided for constructors which produce result
// objects.
func WithTransport(transport http.RoundTripper) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithTransport(transport)
	})
}

// WithTimeout is a ClientOption that specifies HTTP client timeout.
//
//   retriable.New(retriable.WithTimeout(t))
//
// This option cannot be provided for constructors which produce result
// objects.
func WithTimeout(timeout time.Duration) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithTimeout(timeout)
	})
}

// WithDNSServer is a ClientOption that allows to use custom
// dns server for resolution
// dns server must be specified in <host>:<port> format
//
//   retriable.New(retriable.WithDNSServer(dns))
//
// This option cannot be provided for constructors which produce result
// objects.
// Note that WithDNSServer applies changes to http client Transport object
// and hence if used in conjuction with WithTransport method,
// WithDNSServer should be called after WithTransport is called.
//
// retriable.New(retriable.WithTransport(t).WithDNSServer(dns))
//
func WithDNSServer(dns string) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithDNSServer(dns)
	})
}

// Client is custom implementation of http.Client
type Client struct {
	lock       sync.RWMutex
	httpClient *http.Client // Internal HTTP client.
	headers    map[string]string
	Name       string
	Policy     *Policy // Rery policy for http requests
}

// New creates a new Client
func New(opts ...ClientOption) *Client {
	c := &Client{
		Name: "retriable",
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
		Policy: NewDefaultPolicy(),
	}

	for _, opt := range opts {
		opt.applyOption(c)
	}
	return c
}

// WithHeaders adds additional headers to the request
func (c *Client) WithHeaders(headers map[string]string) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.headers == nil {
		c.headers = map[string]string{}
	}

	for key, val := range headers {
		c.headers[key] = val
	}
	return c
}

// AddHeader adds additional header to the request
func (c *Client) AddHeader(header, value string) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.headers == nil {
		c.headers = map[string]string{}
	}

	c.headers[header] = value
	return c
}

// WithName modifies client's name for logging purposes.
func (c *Client) WithName(name string) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.Name = name
	return c
}

// WithPolicy modifies retriable policy.
func (c *Client) WithPolicy(policy *Policy) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.Policy = policy
	return c
}

// WithTLS modifies TLS configuration.
func (c *Client) WithTLS(tlsConfig *tls.Config) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.httpClient.Transport == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConfig
		c.httpClient.Transport = tr

		logger.Infof("reason=new_transport")
	} else {
		c.httpClient.Transport.(*http.Transport).TLSClientConfig = tlsConfig
		logger.Infof("reason=update_transport")
	}
	return c
}

// WithTransport modifies HTTP Transport configuration.
func (c *Client) WithTransport(transport http.RoundTripper) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.httpClient.Transport = transport
	return c
}

// WithTimeout modifies HTTP client timeout.
func (c *Client) WithTimeout(timeout time.Duration) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.httpClient.Timeout = timeout
	return c
}

// WithDNSServer modifies DNS server.
// dns must be specified in <host>:<port> format
func (c *Client) WithDNSServer(dns string) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.httpClient.Transport == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		c.httpClient.Transport = tr
	} else {
		logger.Trace("reason=update_transport")
	}
	c.httpClient.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{}
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, dns)
			},
		}
		return d.DialContext(ctx, network, addr)
	}
	return c
}

// NewDefaultPolicy returns default policy
func NewDefaultPolicy() *Policy {
	return &Policy{
		Retries: map[int]ShouldRetry{
			// 0 is connection related
			0: shouldRetryFactory(5, time.Second*2, "connection"),
			// TooManyRequests (429) is returned when rate limit is exceeded
			http.StatusTooManyRequests: shouldRetryFactory(3, time.Second, "rate-limit"),
			// Unavailble (503) is returned when Cluster knows there's no leader or service is not ready yet
			http.StatusServiceUnavailable: shouldRetryFactory(10, time.Second/2, "unavailable"),
			// Bad Gateway (502) is returned when the node that gets the request thinks
			// there's a leader, but that node is down, treat them both as an election
			// in progress.
			http.StatusBadGateway: shouldRetryFactory(10, time.Second/2, "gateway"),
		},
		TotalRetryLimit: 10,
	}
}

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
func (c *Client) Request(ctx context.Context, method string, hosts []string, path string, requestBody interface{}, responseBody interface{}) (http.Header, int, error) {
	var body io.ReadSeeker

	if requestBody != nil {
		switch val := requestBody.(type) {
		case io.ReadSeeker:
			body = val
		case io.Reader:
			b, err := ioutil.ReadAll(val)
			if err != nil {
				return nil, 0, errors.WithStack(err)
			}
			body = bytes.NewReader(b)
		case []byte:
			body = bytes.NewReader(val)
		case string:
			body = strings.NewReader(val)
		default:
			js, err := json.Marshal(requestBody)
			if err != nil {
				return nil, 0, errors.WithStack(err)
			}
			body = bytes.NewReader(js)
		}
	}
	resp, err := c.executeRequest(ctx, method, hosts, path, body)
	if err != nil {
		return nil, 0, errors.WithStack(err)
	}
	defer resp.Body.Close()

	return c.DecodeResponse(resp, responseBody)
}

// Head makes HEAD request against the specified hosts.
// The supplied hosts are tried in order until one succeeds.
//
// hosts should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
// path should be an absolute URI path, i.e. /foo/bar/baz
func (c *Client) Head(ctx context.Context, hosts []string, path string) (http.Header, int, error) {
	resp, err := c.executeRequest(ctx, http.MethodHead, hosts, path, nil)
	if err != nil {
		return nil, 0, errors.WithStack(err)
	}
	defer resp.Body.Close()
	return resp.Header, resp.StatusCode, nil
}

var noop context.CancelFunc = func() {}

func (c *Client) ensureContext(ctx context.Context, httpMethod, path string) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
		if c.Policy != nil && c.Policy.RequestTimeout > 0 {
			logger.Debugf("method=%s, path=%s, timeout=%v",
				httpMethod, path, c.Policy.RequestTimeout)
			return context.WithTimeout(ctx, c.Policy.RequestTimeout)
		}
	}

	return ctx, noop
}

func (c *Client) executeRequest(ctx context.Context, httpMethod string, hosts []string, path string, body io.ReadSeeker) (*http.Response, error) {
	var many *httperror.ManyError
	var err error
	var resp *http.Response

	// NOTE: do not `defer cancel()` context as it will cause error
	// when reading the body
	ctx, _ = c.ensureContext(ctx, httpMethod, path)

	for i, host := range hosts {
		resp, err = c.doHTTP(ctx, httpMethod, host, path, body)
		if err != nil {
			logger.Errorf("httpMethod=%q, host=%q, path=%q, err=[%+v]",
				httpMethod, host, path, err)
		} else {
			logger.Infof("httpMethod=%q, host=%q, path=%q, status=%v",
				httpMethod, host, path, resp.StatusCode)
		}

		if !c.shouldTryDifferentHost(resp, err) {
			break
		}

		// either success or error
		if err != nil {
			many = many.Add(host, err)
		} else if resp != nil {
			if resp.StatusCode >= 400 {
				many = many.Add(host, httperror.New(resp.StatusCode, "reques_failed", "%s %s %s %s",
					httpMethod, host, path, resp.Status))
			}
			// if not the last host, then close it
			if i < len(hosts)-1 {
				resp.Body.Close()
				resp = nil
			}
		}

		logger.Errorf("err=[%v]", many.Error())

		// rewind the reader
		if body != nil {
			body.Seek(0, 0)
		}
	}

	if resp != nil {
		return resp, nil
	}

	return nil, many
}

// doHTTP wraps calling an HTTP method with retries.
func (c *Client) doHTTP(ctx context.Context, httpMethod string, host string, path string, body io.Reader) (*http.Response, error) {
	uri := host + path

	req, err := http.NewRequest(httpMethod, uri, body)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req = req.WithContext(ctx)

	for header, val := range c.headers {
		req.Header.Add(header, val)
	}

	switch headers := ctx.Value(contextValueForHTTPHeader).(type) {
	case map[string]string:
		for header, val := range headers {
			req.Header.Set(header, val)
		}
		/*
			case map[string][]string:
				for header, list := range headers {
					for _, val := range list {
						req.Header.Add(header, val)
					}
				}
		*/
	}

	return c.Do(req)
}

// Do wraps calling an HTTP method with retries.
func (c *Client) Do(r *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	var retries int

	req, err := convertRequest(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	for retries = 0; ; retries++ {
		// Always rewind the request body when non-nil.
		if req.body != nil {
			body, err := req.body()
			if err != nil {
				return resp, errors.WithStack(err)
			}
			if c, ok := body.(io.ReadCloser); ok {
				req.Request.Body = c
			} else {
				req.Request.Body = ioutil.NopCloser(body)
			}
		}

		resp, err = c.httpClient.Do(req.Request)

		// Check if we should continue with retries.
		shouldRetry, sleepDuration, reason := c.Policy.ShouldRetry(req.Request, resp, err, retries)
		if !shouldRetry {
			break
		}

		desc := fmt.Sprintf("%s %s", req.Request.Method, req.Request.URL)
		if resp != nil {
			if resp.Status != "" {
				desc += " "
				desc += resp.Status
			}
			c.consumeResponseBody(resp)
		}

		logger.Warningf("name=%s, retries=%d, description=%q, reason=%q, sleep=[%v]",
			c.Name, retries, desc, reason, sleepDuration.Seconds())
		time.Sleep(sleepDuration)
	}

	debugRequest(req.Request, err != nil)

	return resp, err
}

// shouldTryDifferentHost returns true if a connection error occurred
// or response has a specific HTTP status:
// - StatusInternalServerError
// - StatusServiceUnavailable
// - StatusGatewayTimeout
// - StatusTooManyRequests
// In that case, the caller should try to send the same request to a different host.
func (c *Client) shouldTryDifferentHost(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return true
	}
	if resp.StatusCode == http.StatusInternalServerError ||
		resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusGatewayTimeout ||
		resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return false
}

// consumeResponseBody is a helper to safely consume the remaining response body
func (c *Client) consumeResponseBody(r *http.Response) {
	if r != nil && r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
	}
}

func debugRequest(r *http.Request, body bool) {
	if logger.LevelAt(xlog.DEBUG) {
		b, err := httputil.DumpRequestOut(r, body)
		if err != nil {
			logger.Errorf("err=[%v]", err.Error())
		} else {
			logger.Debug(string(b))
		}
	}
}

func debugResponse(w *http.Response, body bool) {
	if logger.LevelAt(xlog.DEBUG) {
		b, err := httputil.DumpResponse(w, body)
		if err != nil {
			logger.Errorf("err=[%v]", err.Error())
		} else {
			logger.Debug(string(b))
		}
	}
}

// DecodeResponse will look at the http response, and map it back to either
// the body parameters, or to an error
// [retrying rate limit errors should be done before this]
func (c *Client) DecodeResponse(resp *http.Response, body interface{}) (http.Header, int, error) {
	debugResponse(resp, resp.StatusCode >= 300)
	if resp.StatusCode == http.StatusNoContent {
		return resp.Header, resp.StatusCode, nil
	} else if resp.StatusCode >= http.StatusMultipleChoices { // 300
		e := new(httperror.Error)
		e.HTTPStatus = resp.StatusCode
		bodyCopy := bytes.Buffer{}
		bodyTee := io.TeeReader(resp.Body, &bodyCopy)
		if err := json.NewDecoder(bodyTee).Decode(e); err != nil || e.Code == "" {
			io.Copy(ioutil.Discard, bodyTee) // ensure all of body is read
			// Unable to parse as Error, then return body as error
			return resp.Header, resp.StatusCode, errors.New(string(bodyCopy.Bytes()))
		}
		return resp.Header, resp.StatusCode, e
	}

	switch body.(type) {
	case io.Writer:
		_, err := io.Copy(body.(io.Writer), resp.Body)
		if err != nil {
			return resp.Header, resp.StatusCode, errors.WithMessagef(err, "unable to read body response to (%T) type", body)
		}
	default:
		if err := json.NewDecoder(resp.Body).Decode(body); err != nil {
			return resp.Header, resp.StatusCode, errors.WithMessagef(err, "unable to decode body response to (%T) type", body)
		}
	}

	return resp.Header, resp.StatusCode, nil
}

func shouldRetryFactory(limit int, wait time.Duration, reason string) ShouldRetry {
	return func(r *http.Request, resp *http.Response, err error, retries int) (bool, time.Duration, string) {
		return (limit >= retries), wait, reason
	}
}

var nonRetriableErrors = []string{
	"no such host",
	"TLS handshake error",
	"certificate signed by unknown authority",
	"client didn't provide a certificate",
	"tls: bad certificate",
	"x509: certificate",
	"x509: cannot validate certificate",
	"server gave HTTP response to HTTPS client",
	"dial tcp: lookup",
}

// ShouldRetry returns if connection should be retried
func (p *Policy) ShouldRetry(r *http.Request, resp *http.Response, err error, retries int) (bool, time.Duration, string) {
	if err != nil {
		errStr := err.Error()
		logger.Errorf("host=%q, path=%q, retries=%d, error_type=%T, err=[%s]",
			r.URL.Host, r.URL.Path, retries, err, errStr)

		select {
		case <-r.Context().Done():
			err := r.Context().Err()
			if err == context.Canceled {
				return false, 0, Cancelled
			} else if err == context.DeadlineExceeded {
				return false, 0, DeadlineExceeded
			}
		default:
		}

		if r.TLS != nil {
			logger.Errorf("host=%q, path=%q, complete=%t, mutual=%t, tls_peers=%d, tls_chains=%d",
				r.URL.Host, r.URL.Path,
				resp.TLS.HandshakeComplete,
				resp.TLS.NegotiatedProtocolIsMutual,
				len(resp.TLS.PeerCertificates),
				len(resp.TLS.VerifiedChains))
			for i, c := range resp.TLS.PeerCertificates {
				logger.Errorf("  [%d] CN: %s, Issuer: %s",
					i, c.Subject.CommonName, c.Issuer.CommonName)
			}
		}

		if slices.StringContainsOneOf(errStr, nonRetriableErrors) {
			return false, 0, NonRetriableError
		}

		// On error, use 0 code
		if fn, ok := p.Retries[0]; ok {
			return fn(r, resp, err, retries)
		}
		return false, 0, NonRetriableError
	}

	// Success codes 200-399
	if resp.StatusCode < 400 {
		return false, 0, Success
	}

	if resp.StatusCode == 404 {
		return false, 0, NotFound
	}

	if resp.StatusCode != http.StatusTooManyRequests &&
		resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return false, 0, NonRetriableError
	}

	if p.TotalRetryLimit <= retries {
		return false, 0, LimitExceeded
	}

	if fn, ok := p.Retries[resp.StatusCode]; ok {
		return fn(r, resp, err, retries)
	}

	return false, 0, NonRetriableError
}

// PropagateHeadersFromRequest will set specified headers in the context,
// if present in the request
func PropagateHeadersFromRequest(ctx context.Context, r *http.Request, headers ...string) context.Context {
	values := map[string]string{}
	for _, header := range headers {
		val := r.Header.Get(header)
		if val != "" {
			values[header] = val
		}
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if len(values) > 0 {
		ctx = context.WithValue(ctx, contextValueForHTTPHeader, values)
	}

	return ctx
}

// WithHeaders returns a copy of parent with the provided headers set
func WithHeaders(ctx context.Context, headers map[string]string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	return context.WithValue(ctx, contextValueForHTTPHeader, headers)
}
