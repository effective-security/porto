package retriable

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/x/netutil"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt/dpop"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "retriable")

// Reason strings returned by Policy.ShouldRetry when it stops retrying.
const (
	// Success is returned when the request succeeded (status < 400).
	Success = "success"
	// NotFound is returned when the request returned 404.
	NotFound = "not-found"
	// LimitExceeded is returned when TotalRetryLimit was reached, on 429
	// without a Retries entry, and by RetryAfterShouldRetryFactory when the
	// server asks to wait longer than its maxWait.
	LimitExceeded = "limit-exceeded"
	// DeadlineExceeded is returned when the request context deadline passed.
	DeadlineExceeded = "deadline"
	// Cancelled is returned when the request context was cancelled.
	Cancelled = "cancelled"
	// NonRetriableError is returned for errors and statuses that are never retried.
	NonRetriableError = "non-retriable"
)

const (
	// maxErrorBodySize bounds how much of an error response body
	// DecodeResponse reads, and how much of a retried response body Do
	// drains so that its connection can be reused.
	maxErrorBodySize = 64 << 10

	// defaultTransportPoolSize is the per-host and total connection limit
	// of the transport installed by WithTLS and WithDNSServer when none is
	// set.
	defaultTransportPoolSize = 100

	// defaultMaxRetryAfter is the longest Retry-After wait DefaultPolicy
	// honors for 429; a longer one stops the retries.
	defaultMaxRetryAfter = 30 * time.Second
)

// contextValueName is a custom type to be used as a key in context values map
type contextValueName string

const (
	// ContextValueForHTTPHeader specifies context value name for HTTP headers
	contextValueForHTTPHeader = contextValueName("HTTP-Header")
)

// GenericHTTP defines request helpers that take an explicit host,
// for callers that need to address a server other than the configured one.
type GenericHTTP interface {
	// Request sends a request to the specified host and decodes the response
	// into responseBody.
	// It returns the HTTP headers, status code, and an optional error.
	// For responses with status codes >= 300 (except 204) it converts the
	// response into a Go error, preferably an *httperror.Error.
	// The client's retry Policy and RequestTimeout are applied.
	//
	// host should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
	// path should be an absolute URI path, i.e. /foo/bar/baz
	// requestBody can be io.Reader, []byte, string, or an object to be JSON encoded
	// responseBody can be io.Writer, or a struct to decode JSON into.
	Request(ctx context.Context, method string, host string, path string, requestBody any, responseBody any) (http.Header, int, error)

	// RequestURL is similar to Request but takes a raw URL, from which the
	// host (scheme://host[:port]) and the path are derived.
	RequestURL(ctx context.Context, method, rawURL string, requestBody any, responseBody any) (http.Header, int, error)

	// HeadTo makes a HEAD request against the specified host and returns the
	// response headers and status without decoding a body.
	//
	// host should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
	// path should be an absolute URI path, i.e. /foo/bar/baz
	HeadTo(ctx context.Context, host string, path string) (http.Header, int, error)
}

// HeadRequester defines the HTTP HEAD helper against the configured host.
type HeadRequester interface {
	// Head makes a HEAD request to the configured host.
	// path should be an absolute URI path, i.e. /foo/bar/baz
	Head(ctx context.Context, path string) (http.Header, int, error)
}

// GetRequester defines the HTTP GET helper against the configured host.
type GetRequester interface {
	// Get makes a GET request to the configured host;
	// path should be an absolute URI path, i.e. /foo/bar/baz.
	// The response body is decoded into body (io.Writer or JSON target) and
	// the HTTP headers and status code are returned.
	Get(ctx context.Context, path string, body any) (http.Header, int, error)
}

// PostRequester defines the HTTP POST helper against the configured host.
type PostRequester interface {
	// Post makes an HTTP POST to the supplied path, serializing requestBody to json and sending
	// that as the HTTP body. the HTTP response will be decoded into reponseBody, and the status
	// code (and potentially an error) returned. It'll try and map errors (statusCode >= 300)
	// into a go error, waits & retries for rate limiting errors will be applied based on the
	// client config.
	// path should be an absolute URI path, i.e. /foo/bar/baz
	Post(ctx context.Context, path string, requestBody any, responseBody any) (http.Header, int, error)
}

// PutRequester defines the HTTP PUT helper against the configured host.
type PutRequester interface {
	// Put makes an HTTP PUT to the supplied path, serializing requestBody to json and sending
	// that as the HTTP body. the HTTP response will be decoded into reponseBody, and the status
	// code (and potentially an error) returned. It'll try and map errors (statusCode >= 300)
	// into a go error, waits & retries for rate limiting errors will be applied based on the
	// client config.
	// path should be an absolute URI path, i.e. /foo/bar/baz
	Put(ctx context.Context, path string, requestBody any, responseBody any) (http.Header, int, error)
}

// DeleteRequester defines the HTTP DELETE helper against the configured host.
type DeleteRequester interface {
	// Delete makes a DELETE request to the configured host;
	// path should be an absolute URI path, i.e. /foo/bar/baz.
	// The response body is decoded into body (io.Writer or JSON target) and
	// the HTTP headers and status code are returned.
	Delete(ctx context.Context, path string, body any) (http.Header, int, error)
}

// HTTPClient is the union of the per-method helpers (Head, Get, Post, Put,
// Delete) that operate against the client's configured host.
// *Client implements it.
type HTTPClient interface {
	HeadRequester
	GetRequester
	PostRequester
	PutRequester
	DeleteRequester
}

// NonceRequester is implemented by clients that can attach a replay-nonce
// provider; see NonceProvider.
type NonceRequester interface {
	// SetNonceProvider replaces the nonce provider used by the client.
	SetNonceProvider(provider NonceProvider)
	// GetNonceProvider returns the current nonce provider, or nil.
	GetNonceProvider() NonceProvider
	// WithNonce installs the default provider that fetches nonces with a HEAD
	// request to path and reads them from the headerName response header.
	WithNonce(path, headerName string)
}

// HTTPClientWithNonce is the full client surface: explicit-host requests,
// configured-host helpers and nonce management. *Client implements it.
type HTTPClientWithNonce interface {
	GenericHTTP
	HTTPClient
	NonceRequester
}

// ShouldRetry specifies a policy for handling retries. It is called
// following each request with the response, error values returned by
// the http.Client and the number of already made retries (0 on the first
// call). It returns whether to retry, how long to sleep before the next
// attempt, and a short reason string used for logging (see the Success,
// LimitExceeded, ... constants). If ShouldRetry returns false, the Client
// stops retrying and returns the response to the caller. When retrying, the
// Client drains (up to 64 KiB) and closes the response body; when it stops
// it is up to the caller of Do to close the returned response body.
type ShouldRetry func(r *http.Request, resp *http.Response, err error, retries int) (bool, time.Duration, string)

// BeforeSendRequest is a hook invoked once per request (before retries)
// that may modify or replace the outgoing request.
type BeforeSendRequest func(r *http.Request) *http.Request

// Policy represents the retry policy of a Client.
// Use DefaultPolicy as a starting point.
type Policy struct {

	// Retries specifies a map of HTTP Status code to ShouldRetry function,
	// 0 status code indicates a connection related error (network, TLS, DNS etc.)
	Retries map[int]ShouldRetry

	// TotalRetryLimit is the maximum number of retries across all status codes;
	// once reached ShouldRetry returns LimitExceeded regardless of Retries.
	// Zero or a negative value disables retries.
	TotalRetryLimit int

	// RequestTimeout, when > 0, bounds each call made through Request and the
	// Get/Post/Put/Delete/Head helpers by deriving a context with this timeout.
	// It is not applied by Do.
	RequestTimeout time.Duration

	// NonRetriableErrors is a list of substrings; a transport error whose
	// message contains one of them is never retried.
	// See DefaultNonRetriableErrors.
	NonRetriableErrors []string
}

// A ClientOption modifies the default behavior of Client.
// New applies the options after the host and request policy of the
// ClientConfig, and before its TLS configuration (see New).
type ClientOption interface {
	applyOption(*Client)
}

type optionFunc func(*Client)

func (f optionFunc) applyOption(opts *Client) { f(opts) }

// WithName is a ClientOption that specifies client's name for logging purposes.
//
//	retriable.New(cfg, retriable.WithName("tlsclient"))
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
//	retriable.New(cfg, retriable.WithPolicy(p))
//
// This option cannot be provided for constructors which produce result
// objects.
func WithPolicy(policy Policy) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithPolicy(policy)
	})
}

// WithTLS is a ClientOption that specifies TLS configuration;
// see Client.WithTLS. New returns an error when the transport is not an
// *http.Transport.
//
//	retriable.New(cfg, retriable.WithTLS(t))
//
// This option cannot be provided for constructors which produce result
// objects.
func WithTLS(tlsConfig *tls.Config) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithTLS(tlsConfig)
	})
}

// WithTransport is a ClientOption that specifies HTTP Transport configuration;
// see Client.WithTransport. When cfg.TLS is set, New applies it (unless a
// later WithTLS option sets one) to a clone of the transport; New returns
// an error when that transport is not an *http.Transport.
//
//	retriable.New(cfg, retriable.WithTransport(t))
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
//	retriable.New(cfg, retriable.WithTimeout(t))
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
// dns server must be specified in <host>:<port> format;
// see Client.WithDNSServer. New returns an error when the transport is not
// an *http.Transport.
//
//	retriable.New(cfg, retriable.WithDNSServer(dns))
//
// This option cannot be provided for constructors which produce result
// objects.
// WithTransport replaces the transport, including the DNS setting, so when
// both are used, WithDNSServer must come after WithTransport:
//
//	retriable.New(cfg, retriable.WithTransport(t), retriable.WithDNSServer(dns))
func WithDNSServer(dns string) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithDNSServer(dns)
	})
}

// WithHost is a ClientOption that allows to set the host list.
//
//	retriable.New(cfg, retriable.WithHost(host))
func WithHost(host string) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithHost(host)
	})
}

// WithBeforeSendRequest is a ClientOption that installs a hook
// to modify the request before it's sent.
func WithBeforeSendRequest(hook BeforeSendRequest) ClientOption {
	return optionFunc(func(c *Client) {
		c.beforeSend = hook
	})
}

// WithUserAgent is a ClientOption that adds the User-Agent, X-CLIENT-HOSTNAME
// and X-CLIENT-IP headers to every request; see Client.WithUserAgent.
func WithUserAgent(name string) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithUserAgent(name)
	})
}

// WithCallerIdentity is a ClientOption that installs a token provider used
// to obtain (and refresh on expiry) the Authorization header for each request.
func WithCallerIdentity(ci credentials.CallerIdentity) ClientOption {
	return optionFunc(func(c *Client) {
		c.WithCallerIdentity(ci)
	})
}

// Client is an HTTP client with retries, JSON marshalling, header
// propagation and token-based authorization on top of *http.Client.
// Create it with New, Default, LoadClient or a Factory.
type Client struct {
	// Name identifies the client in logs.
	Name string
	// Policy is the retry policy for HTTP requests; defaults to DefaultPolicy.
	Policy        Policy
	nonceProvider NonceProvider

	// Config is the configuration the client was created from; its Storage
	// is used by SetAuthorization to load tokens and DPoP keys.
	Config ClientConfig

	lock       sync.RWMutex
	httpClient *http.Client // Internal HTTP client.
	host       string
	headers    map[string]string
	beforeSend BeforeSendRequest
	dpopSigner dpop.Signer
	refresh    *callerTokenRefresh

	token          credentials.Token
	callerIdentity credentials.CallerIdentity

	// configErr is set when WithTLS or WithDNSServer could not change the
	// transport; New and Do return it until WithTransport replaces the
	// transport.
	configErr error
	// ownTransport reports that httpClient.Transport was created by WithTLS
	// or WithDNSServer, so its idle connections are closed when it is
	// replaced; a transport passed to WithTransport belongs to the caller.
	ownTransport bool
	// tlsSet reports that WithTLS configured the current transport;
	// WithTransport clears it. New applies ClientConfig.TLS only when it is
	// false after the options.
	tlsSet bool
}

type callerTokenRefresh struct {
	done chan struct{}
	err  error
}

// Default creates a Client for the given host with DefaultPolicy,
// no TLS configuration and no token storage.
func Default(host string) (*Client, error) {
	return New(ClientConfig{Host: host})
}

// New creates a Client from cfg and applies opts on top of it.
// cfg.Request (if set) overrides the RequestTimeout and TotalRetryLimit of
// DefaultPolicy with its non-zero values (see RequestPolicy).
// cfg.TLS (if set) is loaded from files and applied with WithTLS after opts,
// to the transport they leave, so a transport set with WithTransport gets
// it too; only a WithTLS option that no later WithTransport replaced takes
// precedence over cfg.TLS.
// It returns an error when the TLS files cannot be loaded, or when WithTLS
// (including the one for cfg.TLS) or WithDNSServer cannot change the
// transport: one set by WithTransport, or http.DefaultTransport when none
// is set, that is not an *http.Transport.
func New(cfg ClientConfig, opts ...ClientOption) (*Client, error) {
	dopts := []ClientOption{
		WithHost(cfg.Host),
	}

	var tlscfg *tls.Config
	if cfg.TLS != nil {
		var err error
		tlscfg, err = tlsconfig.NewClientTLSFromFiles(
			cfg.TLS.CertFile,
			cfg.TLS.KeyFile,
			cfg.TLS.TrustedCAFile,
		)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to load TLS config")
		}
	}

	if cfg.Request != nil {
		pol := DefaultPolicy()
		pol.RequestTimeout = cmp.Or(cfg.Request.Timeout, pol.RequestTimeout)
		pol.TotalRetryLimit = cmp.Or(cfg.Request.RetryLimit, pol.TotalRetryLimit)
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
	if c.configErr == nil && tlscfg != nil && !c.tlsSet {
		c.WithTLS(tlscfg)
	}
	if c.configErr != nil {
		return nil, c.configErr
	}
	return c, nil
}

// HTTPClient returns the underlying *http.Client, for callers that need
// to tweak it directly. Such changes are not synchronized with requests in
// flight; make them before the client is shared.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// Storage returns the token/key storage of the client's Config,
// creating it from Config.StorageFolder on first use.
func (c *Client) Storage() *Storage {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.Config.Storage()
}

// CurrentHost returns the configured host (scheme://host[:port]).
func (c *Client) CurrentHost() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.host
}

// WithHeaders adds headers that are sent with every request.
func (c *Client) WithHeaders(headers map[string]string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.headers == nil {
		c.headers = map[string]string{}
	}

	for key, val := range headers {
		c.headers[key] = val
	}
	return c
}

// AddHeader adds a header that is sent with every request,
// replacing any previous value for the same name.
func (c *Client) AddHeader(header, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.headers == nil {
		c.headers = map[string]string{}
	}

	c.headers[header] = value
	return c
}

// WithName modifies client's name for logging purposes.
func (c *Client) WithName(name string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Name = name
	return c
}

// WithPolicy modifies retriable policy.
func (c *Client) WithPolicy(policy Policy) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Policy = clonePolicy(policy)
	return c
}

func clonePolicy(policy Policy) Policy {
	policy.Retries = maps.Clone(policy.Retries)
	policy.NonRetriableErrors = append([]string(nil), policy.NonRetriableErrors...)
	return policy
}

// WithHost sets the host (scheme://host[:port]) used by the
// Head/Get/Post/Put/Delete helpers.
func (c *Client) WithHost(host string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.host = host
	return c
}

// WithBeforeSendRequest installs a hook that is invoked once per request
// (before retries) to modify or replace the outgoing request.
func (c *Client) WithBeforeSendRequest(hook BeforeSendRequest) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.beforeSend = hook
	return c
}

// WithCallerIdentity installs a token provider. Before each request the
// client calls GetCallerIdentity when it has no token or the cached token
// has expired, and sets the Authorization header from the result.
func (c *Client) WithCallerIdentity(ci credentials.CallerIdentity) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.callerIdentity = ci
	c.token = credentials.Token{}
	if c.refresh != nil {
		close(c.refresh.done)
		c.refresh = nil
	}
	return c
}

// WithTLS sets the TLS configuration of the transport. It installs a clone
// of the current *http.Transport with TLSClientConfig replaced, so a
// transport supplied with WithTransport (or http.DefaultTransport) is never
// modified; when no transport is set, the clone is made from
// http.DefaultTransport with 100 max (idle) connections per host.
// When the transport is another http.RoundTripper, the configuration cannot
// be applied: New returns an error, and every request fails with that error
// until WithTransport replaces the transport.
func (c *Client) WithTLS(tlsConfig *tls.Config) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()

	tr, err := c.transportClone("TLS configuration")
	if err != nil {
		c.configErr = err
		return c
	}
	tr.TLSClientConfig = tlsConfig
	c.replaceTransport(tr, true)
	c.tlsSet = true
	return c
}

// replaceTransport installs tr, closing the idle connections of the
// replaced transport when the client created it. In-flight requests keep
// using the replaced transport: an HTTP/1.1 connection in use closes when
// it becomes idle, unless a later request on that transport reopens its
// pool; others close after the transport's IdleConnTimeout, if any.
// It must be called with c.lock held.
func (c *Client) replaceTransport(tr http.RoundTripper, own bool) {
	if prev, ok := c.httpClient.Transport.(*http.Transport); ok && c.ownTransport && prev != tr {
		prev.CloseIdleConnections()
	}
	c.httpClient.Transport = tr
	c.ownTransport = own
}

// transportClone returns a copy of the client's *http.Transport to change,
// or a new one when none is set. It must be called with c.lock held.
func (c *Client) transportClone(setting string) (*http.Transport, error) {
	if c.httpClient.Transport == nil {
		dt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.Errorf("unable to apply %s: http.DefaultTransport is %T, not *http.Transport; set a transport with WithTransport",
				setting, http.DefaultTransport)
		}
		tr := dt.Clone()
		tr.MaxIdleConnsPerHost = defaultTransportPoolSize
		tr.MaxConnsPerHost = defaultTransportPoolSize
		tr.MaxIdleConns = defaultTransportPoolSize
		logger.KV(xlog.DEBUG, "reason", "new_transport")
		return tr, nil
	}
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, errors.Errorf("unable to apply %s: transport is %T, not *http.Transport",
			setting, c.httpClient.Transport)
	}
	logger.KV(xlog.DEBUG, "reason", "update_transport")
	return tr.Clone(), nil
}

// WithTransport replaces the HTTP transport, including any TLS or DNS
// setting made before, and clears an error left by WithTLS or WithDNSServer.
// Call it before WithTLS or WithDNSServer, which install modified copies of
// an *http.Transport. The idle connections of a transport that WithTLS or
// WithDNSServer created are closed; the caller's transport is left as is.
// In New, ClientConfig.TLS is applied after the options, so a transport set
// by a WithTransport option is replaced by a clone with that TLS
// configuration unless a later WithTLS option sets one (see New).
// A nil transport, including a nil *http.Transport, selects
// http.DefaultTransport.
func (c *Client) WithTransport(transport http.RoundTripper) *Client {
	if tr, ok := transport.(*http.Transport); ok && tr == nil {
		// a typed nil would panic in Clone and in RoundTrip
		transport = nil
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.replaceTransport(transport, false)
	c.configErr = nil
	c.tlsSet = false
	return c
}

// WithTimeout sets Policy.RequestTimeout, the per-call timeout applied by
// Request and the Get/Post/Put/Delete/Head helpers (not by Do).
func (c *Client) WithTimeout(timeout time.Duration) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Policy.RequestTimeout = timeout
	return c
}

// localIP resolves the X-CLIENT-IP value; tests replace it.
var localIP = netutil.GetLocalIP

// WithUserAgent adds the User-Agent, X-CLIENT-HOSTNAME and X-CLIENT-IP
// headers to every request. The host name and the first non-loopback IPv4
// address are read once, without waiting for the network; a value that
// cannot be resolved is not sent.
func (c *Client) WithUserAgent(name string) *Client {
	headers := map[string]string{
		header.UserAgent: name,
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		headers[header.XClientHostname] = hostname
	}
	if ipaddr, err := localIP(); err == nil && ipaddr != "" {
		headers[header.XClientIP] = ipaddr
	}
	return c.WithHeaders(headers)
}

// WithDNSServer makes the transport resolve names through the given DNS
// server, which must be specified in <host>:<port> format.
// Like WithTLS, it installs a clone of the current *http.Transport (of
// http.DefaultTransport when none is set) with DialContext replaced, and
// records an error returned by New and every request when the transport is
// another http.RoundTripper.
func (c *Client) WithDNSServer(dns string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()

	tr, err := c.transportClone("DNS server")
	if err != nil {
		c.configErr = err
		return c
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
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
	c.replaceTransport(tr, true)
	return c
}

// SetNonceProvider replaces the nonce provider. When set, Request feeds
// every response's headers to it via SetFromHeader.
func (c *Client) SetNonceProvider(provider NonceProvider) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.nonceProvider = provider
}

// GetNonceProvider returns the current nonce provider, or nil.
func (c *Client) GetNonceProvider() NonceProvider {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.nonceProvider
}

// WithNonce installs the default nonce provider (see NewNonceProvider)
// that fetches nonces with HEAD requests to path on the configured host
// and reads them from the headerName response header.
// A leading CurrentHost() prefix in path is stripped.
func (c *Client) WithNonce(path, headerName string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	path = strings.TrimPrefix(path, c.host)

	c.nonceProvider = NewNonceProvider(c, path, headerName)
}

// DefaultPolicy returns the policy used by New: TotalRetryLimit is 5;
// connection errors are retried up to 4 times with a 2s wait
// (DefaultShouldRetryFactory(3, ...) allows retries while the retry count
// is <= 3); 502 and 503 up to 5 times with a 1s wait; 429 up to 3 times,
// waiting for the Retry-After of the response, or 1s without one, and not
// at all when Retry-After asks for more than 30s
// (see RetryAfterShouldRetryFactory). There is no RequestTimeout, and
// DefaultNonRetriableErrors are never retried.
func DefaultPolicy() Policy {
	return Policy{
		Retries: map[int]ShouldRetry{
			// 0 is connection related
			0: DefaultShouldRetryFactory(3, time.Second*2, "connection"),
			// TooManyRequests (429) is returned when rate limit is exceeded
			http.StatusTooManyRequests: RetryAfterShouldRetryFactory(2, time.Second, defaultMaxRetryAfter, "rate-limit"),
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

// RequestURL is similar to Request but takes a raw URL; the host
// (scheme://host[:port]) and the request URI (escaped path, query and
// fragment) are derived from the parsed URL. A URL without a scheme, an
// opaque URL (scheme:opaque) or one with user info (credentials) is an
// error; set credentials with SetAuthorization, WithCallerIdentity or
// headers instead.
func (c *Client) RequestURL(ctx context.Context, method, rawURL string, requestBody any, responseBody any) (http.Header, int, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, errors.WithStack(err)
	}
	if u.Scheme == "" {
		return nil, 0, errors.New("invalid URL: missing scheme")
	}
	if u.Opaque != "" {
		return nil, 0, errors.New("invalid URL: opaque URLs are not supported")
	}
	if u.User != nil {
		return nil, 0, errors.New("invalid URL: user info is not supported")
	}
	// re-escape the host, e.g. the "%" of an IPv6 zone
	host := u.Scheme + "://" + strings.TrimPrefix((&url.URL{Host: u.Host}).String(), "//")
	path := u.RequestURI()
	if u.Fragment != "" {
		path += "#" + u.EscapedFragment()
	}
	return c.Request(ctx, method, host, path, requestBody, responseBody)
}

// Request sends a request to the specified host and decodes the response
// into responseBody (see DecodeResponse).
// It returns the HTTP headers, status code, and an optional error.
// For responses with status codes >= 300 (except 204) it converts the
// response into a Go error, preferably an *httperror.Error.
// The retry Policy and RequestTimeout are applied, a correlation ID is
// attached, and the nonce provider (if any) is fed the response headers.
//
// host should include all the protocol/host/port preamble, e.g. https://foo.bar:3444
// path should be an absolute URI path, i.e. /foo/bar/baz
// requestBody can be io.Reader, []byte, string, or an object to be JSON encoded
// responseBody can be io.Writer, or a struct to decode JSON into.
func (c *Client) Request(ctx context.Context, method string, host string, path string, requestBody any, responseBody any) (http.Header, int, error) {
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

	if nonceProvider := c.GetNonceProvider(); nonceProvider != nil {
		nonceProvider.SetFromHeader(resp.Header)
	}

	return c.DecodeResponse(resp, responseBody)
}

var noop context.CancelFunc = func() {}

func (c *Client) ensureContext(ctx context.Context, httpMethod, path string) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.lock.RLock()
	timeout := c.Policy.RequestTimeout
	c.lock.RUnlock()
	if timeout > 0 {
		logger.KV(xlog.DEBUG,
			"method", httpMethod,
			"path", path,
			"timeout", timeout)
		return context.WithTimeout(ctx, timeout)
	}
	return ctx, noop
}

// cancelOnClose releases the RequestTimeout context of a response when its
// body is closed; the context must outlive the call so the body can be read.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

// Close closes the body and releases the request context.
func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// executeRequest sends the request with RequestTimeout applied; the returned
// body releases the timeout context when closed.
func (c *Client) executeRequest(ctx context.Context, httpMethod string, host string, path string, body io.ReadSeeker) (*http.Response, error) {
	if len(host) == 0 {
		return nil, errors.Errorf("invalid parameter: host")
	}

	ctx, cancel := c.ensureContext(ctx, httpMethod, path)
	ctx = correlation.WithID(ctx)

	resp, err := c.doHTTP(ctx, httpMethod, host, path, body)
	c.lock.RLock()
	name := c.Name
	c.lock.RUnlock()
	if err != nil {
		cancel()
		logger.ContextKV(ctx, xlog.DEBUG,
			"client", name,
			"method", httpMethod,
			"host", host,
			"path", path,
			"err", err)
		return nil, err
	}

	logger.ContextKV(ctx, xlog.DEBUG,
		"client", name,
		"method", httpMethod,
		"host", host,
		"path", path,
		"status", resp.StatusCode)
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
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

// convertRequest wraps http.Request into retriable.Request.
func (c *Client) convertRequest(req *http.Request) (*Request, dpop.Signer, error) {
	c.lock.RLock()
	headers := maps.Clone(c.headers)
	beforeSend := c.beforeSend
	signer := c.dpopSigner
	c.lock.RUnlock()
	for header, val := range headers {
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
	if beforeSend != nil {
		req = beforeSend(req)
	}

	token, configured, err := c.callerToken(ctx)
	if err != nil {
		return nil, nil, err
	}
	if configured && token.AccessToken != "" && (token.Expires == nil || token.Expires.After(time.Now())) {
		authHeader := token.AccessToken
		if token.TokenType != "" {
			authHeader = token.TokenType + " " + authHeader
		}
		req.Header.Set(header.Authorization, authHeader)
	}

	var body io.ReadSeeker
	if req != nil && req.Body != nil {
		defer req.Body.Close()
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
		body = bytes.NewReader(bodyBytes)
	}

	r, err := NewRequest(req.Method, req.URL.String(), body)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	r.Request = r.WithContext(ctx)
	for header, vals := range req.Header {
		for _, val := range vals {
			r.Header.Add(header, val)
		}
	}

	return r, signer, nil
}

// callerToken returns the caller identity token for a request, refreshing
// it when it is missing or expired; the bool is false when no provider is
// set. Concurrent requests share one refresh, made with the context of the
// request that started it; a waiter returns its own context error if that
// ends first, and makes the next call when the shared one failed with a
// context error or WithCallerIdentity replaced the provider meanwhile.
func (c *Client) callerToken(ctx context.Context) (credentials.Token, bool, error) {
	for {
		c.lock.RLock()
		provider := c.callerIdentity
		token := c.token
		c.lock.RUnlock()
		if provider == nil {
			return credentials.Token{}, false, nil
		}
		if callerTokenValid(token) {
			return token, true, nil
		}
		if err := ctx.Err(); err != nil {
			return credentials.Token{}, true, errors.WithStack(err)
		}

		c.lock.Lock()
		provider = c.callerIdentity
		token = c.token
		if provider == nil {
			c.lock.Unlock()
			return credentials.Token{}, false, nil
		}
		if callerTokenValid(token) {
			c.lock.Unlock()
			return token, true, nil
		}
		if c.refresh != nil {
			refresh := c.refresh
			c.lock.Unlock()
			select {
			case <-refresh.done:
				if err := ctx.Err(); err != nil {
					return credentials.Token{}, true, errors.WithStack(err)
				}
				if refresh.err != nil {
					if errors.Is(refresh.err, context.Canceled) || errors.Is(refresh.err, context.DeadlineExceeded) {
						continue
					}
					return credentials.Token{}, true, refresh.err
				}
				continue
			case <-ctx.Done():
				return credentials.Token{}, true, errors.WithStack(ctx.Err())
			}
		}
		refresh := &callerTokenRefresh{done: make(chan struct{})}
		c.refresh = refresh
		c.lock.Unlock()

		token, current, err := c.leadRefresh(ctx, provider, refresh)
		if !current {
			continue
		}
		if err != nil {
			return credentials.Token{}, true, err
		}
		return token, true, nil
	}
}

// leadRefresh makes the provider call of refresh and publishes its result
// to the waiters. current is false when WithCallerIdentity superseded
// refresh and the result was discarded. If the provider panics or calls
// runtime.Goexit, the waiters are released with an error and the panic (or
// Goexit) continues.
func (c *Client) leadRefresh(ctx context.Context, provider credentials.CallerIdentity, refresh *callerTokenRefresh) (token credentials.Token, current bool, err error) {
	panicked := true
	defer func() {
		if panicked {
			c.finishRefresh(refresh, credentials.Token{}, errors.New("caller identity provider panicked"))
		}
	}()
	token, err = fetchCallerToken(ctx, provider)
	panicked = false
	return token, c.finishRefresh(refresh, token, err), err
}

// finishRefresh stores the result of refresh and wakes its waiters. It
// reports false, and changes nothing, when refresh was superseded.
func (c *Client) finishRefresh(refresh *callerTokenRefresh, token credentials.Token, err error) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.refresh != refresh {
		return false
	}
	if err == nil {
		c.token = token
	}
	refresh.err = err
	c.refresh = nil
	close(refresh.done)
	return true
}

// fetchCallerToken calls provider and returns a copy of its token, so a
// provider that keeps the pointer cannot change the stored token.
func fetchCallerToken(ctx context.Context, provider credentials.CallerIdentity) (credentials.Token, error) {
	fresh, err := provider.GetCallerIdentity(ctx)
	if err != nil {
		return credentials.Token{}, errors.WithMessage(err, "unable to get caller identity")
	}
	if fresh == nil {
		return credentials.Token{}, errors.New("caller identity returned no token")
	}
	token := *fresh
	if fresh.Expires != nil {
		expires := *fresh.Expires
		token.Expires = &expires
	}
	return token, nil
}

func callerTokenValid(token credentials.Token) bool {
	return token.AccessToken != "" && (token.Expires == nil || token.Expires.After(time.Now()))
}

// Do sends r with retries according to Policy and returns the final
// response, which the caller must close. It implements Requestor.
// Before sending, the client headers, context-propagated headers
// (see WithHeaders / PropagateHeadersFromRequest), the X-Correlation-ID,
// the BeforeSendRequest hook and caller-identity token are applied once;
// the DPoP proof is signed for each attempt. The body is buffered so it can
// be rewound for each retry.
// Do does not apply Policy.RequestTimeout: bound r's context yourself.
// The wait between attempts ends early when r's context is done, and Do
// then returns an error wrapping the context error. While the context is
// live, a retry that could not start before its deadline is not attempted,
// and the last response (or transport error) is returned instead.
// When retries are exhausted the last response (or transport error) is
// returned; a non-2xx status is not converted to an error here.
// Do returns the error recorded by WithTLS or WithDNSServer when they could
// not change the transport, and closes r.Body.
func (c *Client) Do(r *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	var retries int

	c.lock.RLock()
	policy := c.Policy
	name := c.Name
	// copy the client so that transport setters do not race with this request
	httpClient := *c.httpClient
	configErr := c.configErr
	c.lock.RUnlock()
	if configErr != nil {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, errors.WithStack(configErr)
	}

	req, signer, err := c.convertRequest(r)
	if err != nil {
		return nil, err
	}
	ctx := req.Context()

	for retries = 0; ; retries++ {
		// Always rewind the request body when non-nil.
		if req.body != nil {
			body, err := req.body()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if c, ok := body.(io.ReadCloser); ok {
				req.Body = c
			} else {
				req.Body = io.NopCloser(body)
			}
		}
		if strings.EqualFold(slices.StringUpto(req.Header.Get(header.Authorization), 5), "DPoP ") {
			if signer == nil {
				return nil, errors.New("DPoP signer is not configured")
			}
			if _, err := dpop.ForRequest(signer, req.Request, nil); err != nil {
				return nil, errors.WithMessage(err, "failed to sign DPoP")
			}
		}

		started := time.Now()
		resp, err = httpClient.Do(req.Request)
		elapsed := time.Since(started)
		if err != nil {
			logger.ContextKV(ctx, xlog.WARNING,
				"client", name,
				"retries", retries,
				"host", req.Host,
				"elapsed", elapsed.String(),
				"err", err.Error())
		}
		// Check if we should continue with retries.
		shouldRetry, sleepDuration, reason := policy.ShouldRetry(req.Request, resp, err, retries)
		if !shouldRetry {
			break
		}

		desc := fmt.Sprintf("%s %s", req.Method, req.URL.Redacted())
		if resp != nil && resp.Status != "" {
			desc += " " + resp.Status
		}

		// a retry that cannot start before the deadline returns this response
		if deadline, ok := ctx.Deadline(); ok && ctx.Err() == nil && time.Until(deadline) < sleepDuration {
			logger.ContextKV(ctx, xlog.WARNING,
				"client", name,
				"retries", retries,
				"description", desc,
				"reason", DeadlineExceeded,
				"sleep", sleepDuration)
			break
		}

		drainResponseBody(resp)

		logger.ContextKV(ctx, xlog.WARNING,
			"client", name,
			"retries", retries,
			"description", desc,
			"reason", reason,
			"sleep", sleepDuration)

		if err := waitRetry(ctx, sleepDuration); err != nil {
			return nil, errors.WithMessagef(err, "%s %s: waiting to retry", req.Method, req.URL.Redacted())
		}
	}

	debugRequest(req.Request)

	return resp, err
}

// drainResponseBody reads up to maxErrorBodySize of the body of a response
// that is retried, so that its connection can be reused, and closes it.
func drainResponseBody(r *http.Response) {
	if r != nil && r.Body != nil {
		_, _ = io.CopyN(io.Discard, r.Body, maxErrorBodySize)
		_ = r.Body.Close()
	}
}

// waitRetry waits d, or until ctx is done, in which case it returns the
// context error.
func waitRetry(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return errors.WithStack(err)
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return errors.WithStack(ctx.Err())
	case <-t.C:
		return nil
	}
}

func debugRequest(r *http.Request) {
	if logger.LevelAt(xlog.DEBUG) {
		b, err := DumpRequestOut(r, false)
		if err != nil {
			logger.ContextKV(r.Context(), xlog.ERROR, "err", err.Error())
		} else {
			logger.Debug(string(b))
		}
	}
}

// debugResponse dumps the response headers and the given (already read)
// body at DEBUG level.
func debugResponse(w *http.Response, body []byte) {
	if logger.LevelAt(xlog.DEBUG) {
		b, err := httputil.DumpResponse(w, false)
		if err != nil {
			logger.KV(xlog.ERROR, "err", err.Error())
		} else {
			logger.Debug(string(append(b, body...)))
		}
	}
}

// DecodeResponse maps an HTTP response to either the body parameter or an
// error, and returns the response headers and status code in both cases.
// 204 returns immediately; for a status >= 300 at most 64 KiB of the body
// is read, and it is decoded as an *httperror.Error when it is a JSON error
// document with a "code", otherwise the (possibly truncated) body text
// becomes the error message. For other statuses the body is
// copied into body when it is an io.Writer, or JSON-decoded into it
// (numbers are decoded as json.Number). It does not close resp.Body.
func (c *Client) DecodeResponse(resp *http.Response, body any) (http.Header, int, error) {
	if resp.StatusCode == http.StatusNoContent {
		debugResponse(resp, nil)
		return resp.Header, resp.StatusCode, nil
	} else if resp.StatusCode >= http.StatusMultipleChoices { // 300
		errBody, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		debugResponse(resp, errBody)
		if err != nil {
			return resp.Header, resp.StatusCode, errors.WithMessagef(err, "unable to read response body, status %d", resp.StatusCode)
		}
		e := new(httperror.Error)
		e.HTTPStatus = resp.StatusCode
		if err := json.NewDecoder(bytes.NewReader(errBody)).Decode(e); err != nil || e.Code == "" {
			// Unable to parse as Error, then return body as error
			return resp.Header, resp.StatusCode, errors.New(string(errBody))
		}
		return resp.Header, resp.StatusCode, e
	}
	debugResponse(resp, nil)

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

// DefaultShouldRetryFactory returns a ShouldRetry that retries with a fixed
// wait while the retry count is <= limit, reporting reason.
func DefaultShouldRetryFactory(limit int, wait time.Duration, reason string) ShouldRetry {
	return func(_ *http.Request, _ *http.Response, _ error, retries int) (bool, time.Duration, string) {
		return (limit >= retries), wait, reason
	}
}

// RetryAfterShouldRetryFactory returns a ShouldRetry that, like
// DefaultShouldRetryFactory, retries while the retry count is <= limit,
// but waits for the Retry-After of the response (delay-seconds or an HTTP
// date; a past date means no wait) and uses wait only when the response
// has no valid Retry-After. When Retry-After asks for more than maxWait,
// it does not retry and reports LimitExceeded; a maxWait <= 0 sets no
// bound. Register it for 429 or 503.
func RetryAfterShouldRetryFactory(limit int, wait, maxWait time.Duration, reason string) ShouldRetry {
	return func(_ *http.Request, resp *http.Response, _ error, retries int) (bool, time.Duration, string) {
		if limit < retries {
			return false, wait, reason
		}
		if resp == nil {
			return true, wait, reason
		}
		delay, ok := parseRetryAfter(resp.Header.Get(header.RetryAfter), time.Now())
		if !ok {
			return true, wait, reason
		}
		if maxWait > 0 && delay > maxWait {
			return false, delay, LimitExceeded
		}
		return true, delay, reason
	}
}

// parseRetryAfter parses a Retry-After value (RFC 9110, section 10.2.3):
// delay-seconds, or an HTTP date relative to now. A date in the past is a
// zero delay, and delay-seconds too large for a time.Duration saturate.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		if seconds > uint64(math.MaxInt64/int64(time.Second)) {
			return time.Duration(math.MaxInt64), true
		}
		return time.Duration(seconds) * time.Second, true
	} else if errors.Is(err, strconv.ErrRange) {
		return time.Duration(math.MaxInt64), true
	}
	date, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return max(date.Sub(now), 0), true
}

// DefaultNonRetriableErrors lists substrings of transport error messages
// (DNS, TLS and certificate failures) that the default policy never retries.
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

// ShouldRetry decides whether the attempt should be retried and how long to
// wait first. Order of evaluation: a cancelled or expired request context
// is never retried; TotalRetryLimit is enforced; transport errors matching
// NonRetriableErrors are not retried, others are delegated to Retries[0];
// statuses < 400 succeed; 404 is not retried; 429 is delegated to
// Retries[429] if present and otherwise reports LimitExceeded; other 4xx are
// non-retriable; 5xx are delegated to Retries[status] if present.
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
			switch err {
			case context.Canceled:
				return false, 0, Cancelled
			case context.DeadlineExceeded:
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

	if resp.StatusCode == http.StatusNotFound {
		return false, 0, NotFound
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		if fn, ok := p.Retries[http.StatusTooManyRequests]; ok {
			return fn(r, resp, err, retries)
		}
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

// PropagateHeadersFromRequest returns a context carrying the named headers
// that are present in the incoming request r, so that a Client used with
// that context forwards them on its outgoing requests (see WithHeaders).
// A nil ctx is treated as context.Background().
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

// WithHeaders returns a copy of ctx carrying headers that a Client sets on
// every outgoing request made with that context (overriding client-level
// headers of the same name). It replaces, not merges, headers stored by an
// earlier WithHeaders or PropagateHeadersFromRequest call.
// A nil ctx is treated as context.Background().
func WithHeaders(ctx context.Context, headers map[string]string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	return context.WithValue(ctx, contextValueForHTTPHeader, headers)
}
