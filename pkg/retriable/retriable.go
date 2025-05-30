package retriable

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/x/netutil"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt/dpop"
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
	// host should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
	// path should be an absolute URI path, i.e. /foo/bar/baz
	// requestBody can be io.Reader, []byte, or an object to be JSON encoded
	// responseBody can be io.Writer, or a struct to decode JSON into.
	Request(ctx context.Context, method string, host string, path string, requestBody interface{}, responseBody interface{}) (http.Header, int, error)

	// RequestURL is similar to Request but uses raw URL to one host
	RequestURL(ctx context.Context, method, rawURL string, requestBody interface{}, responseBody interface{}) (http.Header, int, error)

	// HeadTo makes HEAD request against the specified hosts.
	// The supplied hosts are tried in order until one succeeds.
	//
	// host should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
	// path should be an absolute URI path, i.e. /foo/bar/baz
	HeadTo(ctx context.Context, host string, path string) (http.Header, int, error)
}

// HeadRequester defines HTTP Head interface
type HeadRequester interface {
	// Head makes HEAD request.
	// path should be an absolute URI path, i.e. /foo/bar/baz
	// The client must be configured with the hosts list.
	Head(ctx context.Context, path string) (http.Header, int, error)
}

// GetRequester defines HTTP Get interface
type GetRequester interface {
	// Get makes a GET request,
	// path should be an absolute URI path, i.e. /foo/bar/baz
	// the resulting HTTP body will be decoded into the supplied body parameter, and the
	// http status code returned.
	// The client must be configured with the hosts list.
	Get(ctx context.Context, path string, body interface{}) (http.Header, int, error)
}

// PostRequester defines HTTP Post interface
type PostRequester interface {
	// Post makes an HTTP POST to the supplied path, serializing requestBody to json and sending
	// that as the HTTP body. the HTTP response will be decoded into reponseBody, and the status
	// code (and potentially an error) returned. It'll try and map errors (statusCode >= 300)
	// into a go error, waits & retries for rate limiting errors will be applied based on the
	// client config.
	// path should be an absolute URI path, i.e. /foo/bar/baz
	Post(ctx context.Context, path string, requestBody interface{}, responseBody interface{}) (http.Header, int, error)
}

// PutRequester defines HTTP Put interface
type PutRequester interface {
	// Put makes an HTTP PUT to the supplied path, serializing requestBody to json and sending
	// that as the HTTP body. the HTTP response will be decoded into reponseBody, and the status
	// code (and potentially an error) returned. It'll try and map errors (statusCode >= 300)
	// into a go error, waits & retries for rate limiting errors will be applied based on the
	// client config.
	// path should be an absolute URI path, i.e. /foo/bar/baz
	Put(ctx context.Context, path string, requestBody interface{}, responseBody interface{}) (http.Header, int, error)
}

// DeleteRequester defines HTTP Delete interface
type DeleteRequester interface {
	// Delete makes a DELETE request,
	// path should be an absolute URI path, i.e. /foo/bar/baz
	// the resulting HTTP body will be decoded into the supplied body parameter, and the
	// http status code returned.
	Delete(ctx context.Context, path string, body interface{}) (http.Header, int, error)
}

// HTTPClient defines a number of generalized HTTP request handling wrappers
type HTTPClient interface {
	HeadRequester
	GetRequester
	PostRequester
	PutRequester
	DeleteRequester
}

// NonceRequester defines HTTP Nonce interface
type NonceRequester interface {
	SetNonceProvider(provider NonceProvider)
	GetNonceProvider() NonceProvider
	// WithNonce creates nonce provider out of the given header name and path
	WithNonce(path, headerName string)
}

// HTTPClientWithNonce defines a HTTPClient with NonceRequester
type HTTPClientWithNonce interface {
	GenericHTTP
	HTTPClient
	NonceRequester
}

// ShouldRetry specifies a policy for handling retries. It is called
// following each request with the response, error values returned by
// the http.Client and the number of already made retries.
// If ShouldRetry returns false, the Client stops retrying
// and returns the response to the caller. The
// Client will close any response body when retrying, but if the retriable is
// aborted it is up to the caller to properly close any response body before returning.
type ShouldRetry func(r *http.Request, resp *http.Response, err error, retries int) (bool, time.Duration, string)

// BeforeSendRequest allows to modify request before it's sent
type BeforeSendRequest func(r *http.Request) *http.Request

// Policy represents the retriable policy
type Policy struct {

	// Retries specifies a map of HTTP Status code to ShouldRetry function,
	// 0 status code indicates a connection related error (network, TLS, DNS etc.)
	Retries map[int]ShouldRetry

	// Maximum number of retries.
	TotalRetryLimit int

	RequestTimeout time.Duration

	NonRetriableErrors []string
}

// A ClientOption modifies the default behavior of Client.
type ClientOption interface {
	applyOption(*Client)
}

type optionFunc func(*Client)

func (f optionFunc) applyOption(opts *Client) { f(opts) }

// WithName is a ClientOption that specifies client's name for logging purposes.
//
//	retriable.New(retriable.WithName("tlsclient"))
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
//	retriable.New(retriable.WithPolicy(p))
//
// This option cannot be provided for constructors which produce result
// objects.
func WithPolicy(policy Policy) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithPolicy(policy)
	})
}

// WithTLS is a ClientOption that specifies TLS configuration.
//
//	retriable.New(retriable.WithTLS(t))
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
//	retriable.New(retriable.WithTransport(t))
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
//	retriable.New(retriable.WithTimeout(t))
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
//	retriable.New(retriable.WithDNSServer(dns))
//
// This option cannot be provided for constructors which produce result
// objects.
// Note that WithDNSServer applies changes to http client Transport object
// and hence if used in conjuction with WithTransport method,
// WithDNSServer should be called after WithTransport is called.
//
// retriable.New(retriable.WithTransport(t).WithDNSServer(dns))
func WithDNSServer(dns string) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithDNSServer(dns)
	})
}

// WithHost is a ClientOption that allows to set the host list.
//
//	retriable.New(retriable.WithHost(host))
func WithHost(host string) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithHost(host)
	})
}

// WithBeforeSendRequest allows to specify a hook
// to modify request before it's sent
func WithBeforeSendRequest(hook BeforeSendRequest) ClientOption {
	return optionFunc(func(c *Client) {
		c.beforeSend = hook
	})
}

// WithUserAgent adds User-Agent, X-CLIENT-HOSTNAME, X-CLIENT-IP headers.
func WithUserAgent(name string) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithUserAgent(name)
	})
}

// WithCallerIdentity allows to specify token provider
// to modify request before it's sent
func WithCallerIdentity(ci credentials.CallerIdentity) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithCallerIdentity(ci)
	})
}

// Client is custom implementation of http.Client
type Client struct {
	Name             string
	Policy           Policy // Rery policy for http requests
	EnvAuthTokenName string
	nonceProvider    NonceProvider

	Config ClientConfig

	lock       sync.RWMutex
	httpClient *http.Client // Internal HTTP client.
	host       string
	headers    map[string]string
	beforeSend BeforeSendRequest
	dpopSigner dpop.Signer

	token          credentials.Token
	callerIdentity credentials.CallerIdentity
}

// Default creates a default Client for the given host
func Default(host string) (*Client, error) {
	return New(ClientConfig{Host: host})
}

// New creates a new Client
func New(cfg ClientConfig, opts ...ClientOption) (*Client, error) {
	dopts := []ClientOption{}

	if cfg.Host != "" {
		dopts = append(dopts, WithHost(cfg.Host))
	} else if len(cfg.LegacyHosts) > 0 {
		// use legacy hosts if host is not specified
		dopts = append(dopts, WithHost(cfg.LegacyHosts[0]))
	}

	if cfg.TLS != nil {
		tlscfg, err := tlsconfig.NewClientTLSFromFiles(
			cfg.TLS.CertFile,
			cfg.TLS.KeyFile,
			cfg.TLS.TrustedCAFile,
		)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to load TLS config")
		}
		dopts = append(dopts, WithTLS(tlscfg))
	}

	if cfg.Request != nil {
		pol := DefaultPolicy()
		pol.RequestTimeout = cfg.Request.Timeout
		pol.TotalRetryLimit = cfg.Request.RetryLimit
		dopts = append(dopts, WithPolicy(pol))
	}

	dopts = append(dopts, opts...)

	c := &Client{
		Name:       "retriable",
		httpClient: &http.Client{
			//Timeout: time.Second * 30,
		},
		Policy: DefaultPolicy(),
		Config: cfg,
	}

	for _, opt := range dopts {
		opt.applyOption(c)
	}
	return c, nil
}

// HTTPClient returns undelying http.Client
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// Storage returns the current storage
func (c *Client) Storage() *Storage {
	return c.Config.Storage()
}

// CurrentHost returns the current host
func (c *Client) CurrentHost() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.host
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
func (c *Client) WithPolicy(policy Policy) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.Policy = policy
	return c
}

// WithHost sets the host
func (c *Client) WithHost(host string) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.host = host
	return c
}

// WithBeforeSendRequest allows to specify a hook
// to modify request before it's sent
func (c *Client) WithBeforeSendRequest(hook BeforeSendRequest) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.beforeSend = hook
	return c
}

// WithCallerIdentity allows to specify token provider
// to modify request before it's sent
func (c *Client) WithCallerIdentity(ci credentials.CallerIdentity) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.callerIdentity = ci
	return c
}

// WithTLS modifies TLS configuration.
func (c *Client) WithTLS(tlsConfig *tls.Config) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.httpClient.Transport == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxIdleConnsPerHost = 100
		tr.MaxConnsPerHost = 100
		tr.MaxIdleConns = 100
		tr.TLSClientConfig = tlsConfig

		c.httpClient.Transport = tr

		logger.KV(xlog.DEBUG, "reason", "new_transport")
	} else {
		c.httpClient.Transport.(*http.Transport).TLSClientConfig = tlsConfig
		logger.KV(xlog.DEBUG, "reason", "update_transport")
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
	c.Policy.RequestTimeout = timeout
	return c
}

// WithUserAgent adds User-Agent, X-CLIENT-HOSTNAME, X-CLIENT-IP headers.
func (c *Client) WithUserAgent(name string) *Client {
	ipaddr, _ := netutil.WaitForNetwork(time.Second)
	hostname, _ := os.Hostname()
	c.AddHeader(header.UserAgent, name)
	c.AddHeader("X-CLIENT-HOSTNAME", hostname)
	c.AddHeader("X-CLIENT-IP", ipaddr)
	return c
}

// WithDNSServer modifies DNS server.
// dns must be specified in <host>:<port> format
func (c *Client) WithDNSServer(dns string) *Client {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.httpClient.Transport == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxIdleConnsPerHost = 100
		tr.MaxConnsPerHost = 100
		tr.MaxIdleConns = 100

		c.httpClient.Transport = tr
	} else {
		logger.KV(xlog.DEBUG, "reason", "update_transport")
	}
	c.httpClient.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{}
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, dns)
			},
		}
		return d.DialContext(ctx, network, addr)
	}
	return c
}

// SetNonceProvider modifies nonce provider.
func (c *Client) SetNonceProvider(provider NonceProvider) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.nonceProvider = provider
}

// GetNonceProvider returns nonce provider.
func (c *Client) GetNonceProvider() NonceProvider {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.nonceProvider
}

// WithNonce creates default nonce provider.
func (c *Client) WithNonce(path, headerName string) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	path = strings.TrimPrefix(path, c.CurrentHost())

	c.nonceProvider = NewNonceProvider(c, path, headerName)
}

// DefaultPolicy returns default policy
func DefaultPolicy() Policy {
	return Policy{
		Retries: map[int]ShouldRetry{
			// 0 is connection related
			0: DefaultShouldRetryFactory(3, time.Second*2, "connection"),
			// TooManyRequests (429) is returned when rate limit is exceeded
			http.StatusTooManyRequests: DefaultShouldRetryFactory(2, time.Second, "rate-limit"),
			// Unavailble (503) is returned when is not ready yet
			http.StatusServiceUnavailable: DefaultShouldRetryFactory(5, time.Second, "unavailable"),
			// Bad Gateway (502)
			http.StatusBadGateway: DefaultShouldRetryFactory(5, time.Second, "gateway"),
		},
		//RequestTimeout:     6 * time.Second,
		TotalRetryLimit:    5,
		NonRetriableErrors: DefaultNonRetriableErrors,
	}
}

// RequestURL is similar to Request but uses raw URL to one host
func (c *Client) RequestURL(ctx context.Context, method, rawURL string, requestBody interface{}, responseBody interface{}) (http.Header, int, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, errors.WithStack(err)
	}
	host := u.Scheme + "://" + u.Host
	path := rawURL[len(host):]
	return c.Request(ctx, method, host, path, requestBody, responseBody)
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
func (c *Client) Request(ctx context.Context, method string, host string, path string, requestBody interface{}, responseBody interface{}) (http.Header, int, error) {
	var body io.ReadSeeker

	if requestBody != nil {
		switch val := requestBody.(type) {
		case io.ReadSeeker:
			body = val
		case io.Reader:
			b, err := io.ReadAll(val)
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
	resp, err := c.executeRequest(ctx, method, host, path, body)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if c.nonceProvider != nil {
		c.nonceProvider.SetFromHeader(resp.Header)
	}

	return c.DecodeResponse(resp, responseBody)
}

var noop context.CancelFunc = func() {}

func (c *Client) ensureContext(ctx context.Context, httpMethod, path string) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.Policy.RequestTimeout > 0 {
		logger.KV(xlog.DEBUG,
			"method", httpMethod,
			"path", path,
			"timeout", c.Policy.RequestTimeout)
		return context.WithTimeout(ctx, c.Policy.RequestTimeout)
	}
	return ctx, noop
}

func (c *Client) executeRequest(ctx context.Context, httpMethod string, host string, path string, body io.ReadSeeker) (*http.Response, error) {
	if len(host) == 0 {
		return nil, errors.Errorf("invalid parameter: host")
	}

	var err error
	var resp *http.Response

	// NOTE: do not `defer cancel()` context as it will cause error
	// when reading the body
	ctx, _ = c.ensureContext(ctx, httpMethod, path)
	ctx = correlation.WithID(ctx)

	resp, err = c.doHTTP(ctx, httpMethod, host, path, body)
	if err != nil {
		logger.ContextKV(ctx, xlog.DEBUG,
			"client", c.Name,
			"method", httpMethod,
			"host", host,
			"path", path,
			"err", err)
	} else {
		logger.ContextKV(ctx, xlog.DEBUG,
			"client", c.Name,
			"method", httpMethod,
			"host", host,
			"path", path,
			"status", resp.StatusCode)
	}

	// either success or error
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// doHTTP wraps calling an HTTP method with retries.
func (c *Client) doHTTP(ctx context.Context, httpMethod string, host string, path string, body io.Reader) (*http.Response, error) {
	uri := host + path

	req, err := http.NewRequest(httpMethod, uri, body)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req = req.WithContext(ctx)
	return c.Do(req)
}

// convertRequest wraps http.Request into retriable.Request
func (c *Client) convertRequest(req *http.Request) (*Request, error) {
	for header, val := range c.headers {
		req.Header.Add(header, val)
	}

	ctx := req.Context()
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

	if req.Header.Get(header.XCorrelationID) == "" {
		req.Header.Add(header.XCorrelationID, correlation.ID(ctx))
	}
	if c.beforeSend != nil {
		req = c.beforeSend(req)
	}

	if c.callerIdentity != nil {
		if c.token.AccessToken == "" || (c.token.Expires != nil && c.token.Expires.Before(time.Now())) {
			ti, err := c.callerIdentity.GetCallerIdentity(ctx)
			if err != nil {
				return nil, err
			}
			c.token = *ti
		}

		if c.token.AccessToken != "" && (c.token.Expires == nil || c.token.Expires.After(time.Now())) {
			authHeader := c.token.AccessToken
			if c.token.TokenType != "" {
				authHeader = c.token.TokenType + " " + authHeader
			}
			req.Header.Set(header.Authorization, authHeader)
		}
	}

	authHeader := req.Header.Get(header.Authorization)
	if strings.EqualFold(slices.StringUpto(authHeader, 5), "DPoP ") {
		_, err := dpop.ForRequest(c.dpopSigner, req, nil)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to sign DPoP")
		}
	}

	var body io.ReadSeeker
	if req != nil && req.Body != nil {
		defer req.Body.Close()
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		body = bytes.NewReader(bodyBytes)
	}

	r, err := NewRequest(req.Method, req.URL.String(), body)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	r.Request = r.WithContext(ctx)
	for header, vals := range req.Header {
		for _, val := range vals {
			r.Request.Header.Add(header, val)
		}
	}

	return r, nil
}

// Do wraps calling an HTTP method with retries.
func (c *Client) Do(r *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	var retries int

	req, err := c.convertRequest(r)
	if err != nil {
		return nil, err
	}

	for retries = 0; ; retries++ {
		// Always rewind the request body when non-nil.
		if req.body != nil {
			body, err := req.body()
			if err != nil {
				return resp, err
			}
			if c, ok := body.(io.ReadCloser); ok {
				req.Request.Body = c
			} else {
				req.Request.Body = io.NopCloser(body)
			}
		}

		started := time.Now()
		resp, err = c.httpClient.Do(req.Request)
		elapsed := time.Since(started)
		if err != nil {
			logger.ContextKV(r.Context(), xlog.WARNING,
				"client", c.Name,
				"retries", retries,
				"host", req.Host,
				"elapsed", elapsed.String(),
				"err", err.Error())
		}
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

		logger.ContextKV(r.Context(), xlog.WARNING,
			"client", c.Name,
			"retries", retries,
			"description", desc,
			"reason", reason,
			"sleep", sleepDuration)

		time.Sleep(sleepDuration)
	}

	debugRequest(req.Request, err != nil)

	return resp, err
}

// consumeResponseBody is a helper to safely consume the remaining response body
func (c *Client) consumeResponseBody(r *http.Response) {
	if r != nil && r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
	}
}

func debugRequest(r *http.Request, body bool) {
	if logger.LevelAt(xlog.DEBUG) {
		b, err := DumpRequestOut(r, body)
		if err != nil {
			logger.ContextKV(r.Context(), xlog.ERROR, "err", err.Error())
		} else {
			logger.Debug(string(b))
		}
	}
}

func debugResponse(w *http.Response, body bool) {
	if logger.LevelAt(xlog.DEBUG) {
		b, err := httputil.DumpResponse(w, body)
		if err != nil {
			logger.KV(xlog.ERROR, "err", err.Error())
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
			_, _ = io.Copy(io.Discard, bodyTee) // ensure all of body is read
			// Unable to parse as Error, then return body as error
			return resp.Header, resp.StatusCode, errors.New(bodyCopy.String())
		}
		return resp.Header, resp.StatusCode, e
	}

	switch typ := body.(type) {
	case io.Writer:
		_, err := io.Copy(typ, resp.Body)
		if err != nil {
			return resp.Header, resp.StatusCode, errors.WithMessagef(err, "unable to read body response to (%T) type", body)
		}
	default:
		d := json.NewDecoder(resp.Body)
		d.UseNumber()
		if err := d.Decode(body); err != nil {
			return resp.Header, resp.StatusCode, errors.WithMessagef(err, "unable to decode body response to (%T) type", body)
		}
	}

	return resp.Header, resp.StatusCode, nil
}

// DefaultShouldRetryFactory returns default ShouldRetry
func DefaultShouldRetryFactory(limit int, wait time.Duration, reason string) ShouldRetry {
	return func(_ *http.Request, _ *http.Response, _ error, retries int) (bool, time.Duration, string) {
		return (limit >= retries), wait, reason
	}
}

// DefaultNonRetriableErrors provides a list of default errors,
// that cleint will not retry on
var DefaultNonRetriableErrors = []string{
	"no such host",
	"TLS handshake error",
	"certificate signed by unknown authority",
	"client didn't provide a certificate",
	"tls: bad certificate",
	"x509: certificate",
	"x509: cannot validate certificate",
	"server gave HTTP response to HTTPS client",
	"dial tcp: lookup",
	"peer reset",
}

// ShouldRetry returns if connection should be retried
func (p *Policy) ShouldRetry(r *http.Request, resp *http.Response, err error, retries int) (bool, time.Duration, string) {
	ctx := r.Context()
	if err != nil {
		errStr := err.Error()
		logger.ContextKV(ctx, xlog.DEBUG,
			"host", r.URL.Host,
			"path", r.URL.Path,
			"retries", retries,
			"err", errStr)

		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err == context.Canceled {
				return false, 0, Cancelled
			} else if err == context.DeadlineExceeded {
				return false, 0, DeadlineExceeded
			}
		default:
		}

		/*
			if r.TLS != nil {
				logger.Errorf("host=%q, path=%q, complete=%t, tls_peers=%d, tls_chains=%d",
					r.URL.Host, r.URL.Path,
					resp.TLS.HandshakeComplete,
					len(resp.TLS.PeerCertificates),
					len(resp.TLS.VerifiedChains))
				for i, c := range resp.TLS.PeerCertificates {
					logger.Errorf("  [%d] CN: %s, Issuer: %s",
						i, c.Subject.CommonName, c.Issuer.CommonName)
				}
			}
		*/

		if p.TotalRetryLimit <= retries {
			return false, 0, LimitExceeded
		}

		if slices.StringContainsOneOf(errStr, p.NonRetriableErrors) {
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

	logger.ContextKV(ctx, xlog.WARNING,
		"host", r.URL.Host,
		"path", r.URL.Path,
		"retries", retries,
		"status", resp.StatusCode)

	if p.TotalRetryLimit <= retries {
		return false, 0, LimitExceeded
	}

	if resp.StatusCode == 404 {
		return false, 0, NotFound
	}

	if resp.StatusCode == 429 {
		return false, 0, LimitExceeded
	}

	if resp.StatusCode < 500 {
		return false, 0, NonRetriableError
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
