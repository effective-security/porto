package retriable_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/x/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxErrorBody is how much of an error response body the client reads,
// and how much of a retried response body it drains.
const maxErrorBody = 64 << 10

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// trackingBody records how much of a response body was read and whether it
// was closed.
type trackingBody struct {
	r      io.Reader
	read   atomic.Int64
	closed atomic.Bool
}

func newTrackingBody(s string) *trackingBody {
	return &trackingBody{r: strings.NewReader(s)}
}

func (b *trackingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.read.Add(int64(n))
	return n, err
}

func (b *trackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func testResponse(r *http.Request, status int, body io.ReadCloser, hdr http.Header) *http.Response {
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     hdr,
		Body:       body,
		Request:    r,
	}
}

func TestRequestPolicyKeepsDefaults(t *testing.T) {
	t.Parallel()

	def := retriable.DefaultPolicy()
	tcases := []struct {
		name       string
		request    *retriable.RequestPolicy
		retryLimit int
		timeout    time.Duration
	}{
		{name: "absent", retryLimit: def.TotalRetryLimit},
		{name: "empty", request: &retriable.RequestPolicy{}, retryLimit: def.TotalRetryLimit},
		{name: "timeout only", request: &retriable.RequestPolicy{Timeout: 2 * time.Second}, retryLimit: def.TotalRetryLimit, timeout: 2 * time.Second},
		{name: "both", request: &retriable.RequestPolicy{RetryLimit: 3, Timeout: time.Second}, retryLimit: 3, timeout: time.Second},
		{name: "retries disabled", request: &retriable.RequestPolicy{RetryLimit: -1}, retryLimit: -1},
		// a negative timeout is kept and, like zero, applies no timeout
		{name: "negative timeout", request: &retriable.RequestPolicy{Timeout: -time.Second}, retryLimit: def.TotalRetryLimit, timeout: -time.Second},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := retriable.New(retriable.ClientConfig{Request: tc.request})
			require.NoError(t, err)
			assert.Equal(t, tc.retryLimit, c.Policy.TotalRetryLimit)
			assert.Equal(t, tc.timeout, c.Policy.RequestTimeout)
			assert.Len(t, c.Policy.Retries, len(def.Retries))
			assert.Equal(t, def.NonRetriableErrors, c.Policy.NonRetriableErrors)
		})
	}
}

func TestRequestPolicyFromYAML(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	dir := t.TempDir()
	write := func(name, request string) string {
		file := filepath.Join(dir, name)
		cfg := "host: " + server.URL + "\nrequest:\n" + request
		require.NoError(t, os.WriteFile(file, []byte(cfg), 0o600))
		return file
	}

	// a request block without retry_limit keeps the default retry limit
	c, err := retriable.LoadClient(write("timeout.yaml", "  timeout: 2s\n"))
	require.NoError(t, err)
	assert.Equal(t, retriable.DefaultPolicy().TotalRetryLimit, c.Policy.TotalRetryLimit)
	assert.Equal(t, 2*time.Second, c.Policy.RequestTimeout)

	// a negative retry_limit disables retries
	c, err = retriable.LoadClient(write("noretry.yaml", "  retry_limit: -1\n"))
	require.NoError(t, err)
	assert.Equal(t, -1, c.Policy.TotalRetryLimit)
	assert.Zero(t, c.Policy.RequestTimeout)

	_, status, err := c.Get(context.Background(), "/", nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, int32(1), calls.Load())
}

func TestShouldRetryTooManyRequests(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	res := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}

	// without a Retries entry 429 is not retried
	p := retriable.Policy{TotalRetryLimit: 5}
	should, wait, reason := p.ShouldRetry(req, res, nil, 0)
	assert.False(t, should)
	assert.Zero(t, wait)
	assert.Equal(t, retriable.LimitExceeded, reason)

	// a Retries entry is consulted
	p.Retries = map[int]retriable.ShouldRetry{
		http.StatusTooManyRequests: retriable.DefaultShouldRetryFactory(1, time.Millisecond, "custom"),
	}
	should, wait, reason = p.ShouldRetry(req, res, nil, 1)
	assert.True(t, should)
	assert.Equal(t, time.Millisecond, wait)
	assert.Equal(t, "custom", reason)

	// TotalRetryLimit still applies first
	should, _, reason = p.ShouldRetry(req, res, nil, 5)
	assert.False(t, should)
	assert.Equal(t, retriable.LimitExceeded, reason)

	// DefaultPolicy waits for Retry-After and gives up when it is too long
	def := retriable.DefaultPolicy()
	res.Header.Set(header.RetryAfter, "3")
	should, wait, reason = def.ShouldRetry(req, res, nil, 0)
	assert.True(t, should)
	assert.Equal(t, 3*time.Second, wait)
	assert.Equal(t, "rate-limit", reason)

	res.Header.Set(header.RetryAfter, "31")
	should, wait, reason = def.ShouldRetry(req, res, nil, 0)
	assert.False(t, should)
	assert.Equal(t, 31*time.Second, wait)
	assert.Equal(t, retriable.LimitExceeded, reason)
}

func TestRetryAfterShouldRetryFactory(t *testing.T) {
	t.Parallel()

	const (
		wait      = time.Second
		maxWait   = 30 * time.Second
		rateLimit = "rate-limit"
	)
	saturated := time.Duration(math.MaxInt64)
	bounded := retriable.RetryAfterShouldRetryFactory(2, wait, maxWait, rateLimit)
	unbounded := retriable.RetryAfterShouldRetryFactory(2, wait, 0, rateLimit)

	tcases := []struct {
		name       string
		fn         retriable.ShouldRetry
		retryAfter string
		noResponse bool
		retries    int
		expected   bool
		expWait    time.Duration
		expReason  string
	}{
		{name: "limit reached", fn: bounded, retryAfter: "1", retries: 3, expWait: wait, expReason: rateLimit},
		{name: "transport error", fn: bounded, noResponse: true, expected: true, expWait: wait, expReason: rateLimit},
		{name: "no header", fn: bounded, expected: true, expWait: wait, expReason: rateLimit},
		{name: "seconds at limit", fn: bounded, retryAfter: "2", retries: 2, expected: true, expWait: 2 * time.Second, expReason: rateLimit},
		{name: "seconds with spaces", fn: bounded, retryAfter: " 3 ", expected: true, expWait: 3 * time.Second, expReason: rateLimit},
		{name: "zero", fn: bounded, retryAfter: "0", expected: true, expReason: rateLimit},
		{name: "at max wait", fn: bounded, retryAfter: "30", expected: true, expWait: maxWait, expReason: rateLimit},
		{name: "above max wait", fn: bounded, retryAfter: "31", expWait: 31 * time.Second, expReason: retriable.LimitExceeded},
		{name: "duration overflow", fn: bounded, retryAfter: "9223372036854775807", expWait: saturated, expReason: retriable.LimitExceeded},
		{name: "uint64 overflow", fn: bounded, retryAfter: "99999999999999999999", expWait: saturated, expReason: retriable.LimitExceeded},
		{name: "negative", fn: bounded, retryAfter: "-1", expected: true, expWait: wait, expReason: rateLimit},
		{name: "fraction", fn: bounded, retryAfter: "1.5", expected: true, expWait: wait, expReason: rateLimit},
		{name: "invalid", fn: bounded, retryAfter: "soon", expected: true, expWait: wait, expReason: rateLimit},
		{name: "past date", fn: bounded, retryAfter: "Wed, 21 Oct 2015 07:28:00 GMT", expected: true, expReason: rateLimit},
		{name: "no max wait", fn: unbounded, retryAfter: "3600", expected: true, expWait: time.Hour, expReason: rateLimit},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var res *http.Response
			if !tc.noResponse {
				res = &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
				if tc.retryAfter != "" {
					res.Header.Set(header.RetryAfter, tc.retryAfter)
				}
			}
			should, wait, reason := tc.fn(nil, res, nil, tc.retries)
			assert.Equal(t, tc.expected, should)
			assert.Equal(t, tc.expWait, wait)
			assert.Equal(t, tc.expReason, reason)
		})
	}

	t.Run("future date", func(t *testing.T) {
		t.Parallel()
		res := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
		res.Header.Set(header.RetryAfter, time.Now().Add(10*time.Second).UTC().Format(http.TimeFormat))
		should, wait, reason := bounded(nil, res, nil, 0)
		assert.True(t, should)
		// the HTTP date has a one second resolution
		assert.InDelta(t, float64(10*time.Second), float64(wait), float64(2*time.Second))
		assert.Equal(t, rateLimit, reason)
	})
}

func TestDoRetriesTooManyRequests(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			w.Header().Set(header.RetryAfter, "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	client, err := retriable.Default(server.URL)
	require.NoError(t, err)

	var res map[string]string
	_, status, err := client.Get(context.Background(), "/", &res)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "ok", res["status"])
	assert.Equal(t, int32(3), calls.Load())
}

func TestDoStopsOnLongRetryAfter(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set(header.RetryAfter, "120")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "slow down")
	}))
	defer server.Close()

	client, err := retriable.Default(server.URL)
	require.NoError(t, err)

	started := time.Now()
	_, status, err := client.Get(context.Background(), "/", nil)
	require.EqualError(t, err, "slow down")
	assert.Equal(t, http.StatusTooManyRequests, status)
	assert.Equal(t, int32(1), calls.Load())
	assert.Less(t, time.Since(started), 10*time.Second)
}

func TestDoWaitEndsWhenContextIsCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	body := newTrackingBody("unavailable")
	client, err := retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			// cancel while Do waits to retry
			time.AfterFunc(20*time.Millisecond, cancel)
			return testResponse(r, http.StatusServiceUnavailable, body, nil), nil
		})),
		retriable.WithPolicy(retriable.Policy{
			TotalRetryLimit: 3,
			Retries: map[int]retriable.ShouldRetry{
				http.StatusServiceUnavailable: retriable.DefaultShouldRetryFactory(3, time.Minute, "unavailable"),
			},
		}),
	)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.test/v1", nil)
	require.NoError(t, err)

	started := time.Now()
	resp, err := client.Do(req)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, context.Canceled)
	assert.EqualError(t, err, "GET https://api.test/v1: waiting to retry: context canceled")
	assert.Less(t, time.Since(started), 10*time.Second)
	assert.Equal(t, int32(1), calls.Load())
	assert.True(t, body.closed.Load())
}

func TestDoReturnsResponseWhenRetryWouldPassDeadline(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var calls atomic.Int32
	body := newTrackingBody("unavailable")
	client, err := retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			return testResponse(r, http.StatusServiceUnavailable, body, nil), nil
		})),
		retriable.WithPolicy(retriable.Policy{
			TotalRetryLimit: 3,
			Retries: map[int]retriable.ShouldRetry{
				http.StatusServiceUnavailable: retriable.DefaultShouldRetryFactory(3, time.Minute, "unavailable"),
			},
		}),
	)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.test/v1", nil)
	require.NoError(t, err)

	started := time.Now()
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Less(t, time.Since(started), 5*time.Second)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, int32(1), calls.Load())
	assert.False(t, body.closed.Load())
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "unavailable", string(b))
	require.NoError(t, resp.Body.Close())
}

func TestDoReturnsTransportErrorWhenRetryWouldPassDeadline(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var calls atomic.Int32
	errDial := errors.New("connection refused")
	client, err := retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(roundTripperFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, errDial
		})),
		retriable.WithPolicy(retriable.Policy{
			TotalRetryLimit: 3,
			Retries: map[int]retriable.ShouldRetry{
				0: retriable.DefaultShouldRetryFactory(3, time.Minute, "connection"),
			},
		}),
	)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.test/v1", nil)
	require.NoError(t, err)

	started := time.Now()
	resp, err := client.Do(req)
	assert.Nil(t, resp)
	require.ErrorIs(t, err, errDial)
	assert.EqualError(t, err, `Get "https://api.test/v1": connection refused`)
	assert.Less(t, time.Since(started), 5*time.Second)
	assert.Equal(t, int32(1), calls.Load())
}

func TestDoDoesNotRetryAfterContextIsDone(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	client, err := retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			cancel()
			return testResponse(r, http.StatusServiceUnavailable, io.NopCloser(strings.NewReader("unavailable")), nil), nil
		})),
		retriable.WithPolicy(retriable.Policy{
			TotalRetryLimit: 3,
			Retries: map[int]retriable.ShouldRetry{
				http.StatusServiceUnavailable: retriable.DefaultShouldRetryFactory(3, 0, "unavailable"),
			},
		}),
	)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.test/v1", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	assert.Nil(t, resp)
	require.ErrorIs(t, err, context.Canceled)
	assert.EqualError(t, err, "GET https://api.test/v1: waiting to retry: context canceled")
	assert.Equal(t, int32(1), calls.Load())
}

func TestDoDrainsAndClosesRetriedBodies(t *testing.T) {
	t.Parallel()

	large := strings.Repeat("x", 1<<20)
	bodies := []*trackingBody{
		newTrackingBody(large),
		newTrackingBody(large),
		newTrackingBody(`{}`),
	}
	var calls atomic.Int32
	client, err := retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			i := calls.Add(1) - 1
			status := http.StatusOK
			if i < 2 {
				status = http.StatusServiceUnavailable
			}
			return testResponse(r, status, bodies[i], nil), nil
		})),
		retriable.WithPolicy(retriable.Policy{
			TotalRetryLimit: 5,
			Retries: map[int]retriable.ShouldRetry{
				http.StatusServiceUnavailable: retriable.DefaultShouldRetryFactory(5, 0, "unavailable"),
			},
		}),
	)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://api.test/v1", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(3), calls.Load())
	for _, b := range bodies[:2] {
		assert.True(t, b.closed.Load())
		assert.Equal(t, int64(maxErrorBody), b.read.Load())
	}
	// the returned body belongs to the caller
	assert.False(t, bodies[2].closed.Load())
	require.NoError(t, resp.Body.Close())
	assert.True(t, bodies[2].closed.Load())
}

func TestRequestReleasesTimeoutContext(t *testing.T) {
	t.Parallel()

	var (
		mu      sync.Mutex
		last    context.Context
		errBoom = errors.New("boom")
		fail    atomic.Bool
	)
	lastContext := func() context.Context {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
	client, err := retriable.New(retriable.ClientConfig{Host: "https://api.test"},
		retriable.WithTransport(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			last = r.Context()
			mu.Unlock()
			if fail.Load() {
				return nil, errBoom
			}
			return testResponse(r, http.StatusOK, io.NopCloser(strings.NewReader(`{}`)), nil), nil
		})),
		retriable.WithPolicy(retriable.Policy{RequestTimeout: time.Hour}),
	)
	require.NoError(t, err)

	ctx := context.Background()
	var res map[string]any
	_, status, err := client.Get(ctx, "/v1", &res)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	_, ok := lastContext().Deadline()
	assert.True(t, ok)
	assert.ErrorIs(t, lastContext().Err(), context.Canceled)

	_, status, err = client.HeadTo(ctx, "https://api.test", "/v1")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.ErrorIs(t, lastContext().Err(), context.Canceled)

	fail.Store(true)
	_, _, err = client.Get(ctx, "/v1", &res)
	require.ErrorIs(t, err, errBoom)
	assert.ErrorIs(t, lastContext().Err(), context.Canceled)
	assert.NoError(t, ctx.Err())
}

func TestRequestURL(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		urls  []*url.URL
		calls int
	)
	client, err := retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			u := *r.URL
			urls = append(urls, &u)
			calls++
			mu.Unlock()
			return testResponse(r, http.StatusOK, io.NopCloser(strings.NewReader(`{}`)), nil), nil
		})),
	)
	require.NoError(t, err)

	tcases := []struct {
		name     string
		rawURL   string
		scheme   string
		host     string
		uri      string
		fragment string
		err      string
	}{
		{name: "path query fragment", rawURL: "https://api.test/v1/test?qq#ff", scheme: "https", host: "api.test", uri: "/v1/test?qq", fragment: "ff"},
		// the escaped host is shorter once decoded, which broke byte offsets
		{name: "escaped host", rawURL: "https://%C3%A9x.test/v1/test?q=1", scheme: "https", host: "éx.test", uri: "/v1/test?q=1"},
		{name: "escaped path", rawURL: "https://api.test/v1/a%2Fb?x=%20y", scheme: "https", host: "api.test", uri: "/v1/a%2Fb?x=%20y"},
		{name: "no path", rawURL: "https://api.test", scheme: "https", host: "api.test", uri: "/"},
		{name: "upper-case scheme", rawURL: "HTTPS://api.test:8443/x", scheme: "https", host: "api.test:8443", uri: "/x"},
		{name: "IPv6 zone", rawURL: "https://[fe80::1%25en0]:8080/x", scheme: "https", host: "[fe80::1%en0]:8080", uri: "/x"},
		{name: "opaque", rawURL: "https:api.test/v1", err: "invalid URL: opaque URLs are not supported"},
		{name: "user info", rawURL: "https://user:secret@api.test/x", err: "invalid URL: user info is not supported"},
		{name: "missing scheme", rawURL: "/v1/x", err: "invalid URL: missing scheme"},
		{name: "invalid escape", rawURL: "https://api.test/%zz", err: `parse "https://api.test/%zz": invalid URL escape "%zz"`},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			before := calls
			mu.Unlock()

			var res map[string]any
			_, status, err := client.RequestURL(context.Background(), http.MethodGet, tc.rawURL, nil, &res)

			mu.Lock()
			defer mu.Unlock()
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				assert.Zero(t, status)
				assert.Equal(t, before, calls)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, status)
			require.Equal(t, before+1, calls)
			u := urls[len(urls)-1]
			assert.Equal(t, tc.scheme, u.Scheme)
			assert.Equal(t, tc.host, u.Host)
			assert.Equal(t, tc.uri, u.RequestURI())
			assert.Equal(t, tc.fragment, u.Fragment)
		})
	}
}

func TestDecodeResponseBoundsErrorBody(t *testing.T) {
	t.Parallel()

	c, err := retriable.New(retriable.ClientConfig{})
	require.NoError(t, err)

	body := newTrackingBody(strings.Repeat("x", 1<<20))
	res := &http.Response{StatusCode: http.StatusBadGateway, Header: http.Header{}, Body: body}
	_, status, err := c.DecodeResponse(res, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, status)
	assert.Equal(t, strings.Repeat("x", maxErrorBody), err.Error())
	assert.Equal(t, int64(maxErrorBody), body.read.Load())

	// a read error is returned instead of the partial body
	errRead := errors.New("connection reset")
	res = &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     http.Header{},
		Body:       io.NopCloser(io.MultiReader(strings.NewReader(`{"code":`), iotest.ErrReader(errRead))),
	}
	_, status, err = c.DecodeResponse(res, nil)
	require.ErrorIs(t, err, errRead)
	assert.EqualError(t, err, "unable to read response body, status 500: connection reset")
	assert.Equal(t, http.StatusInternalServerError, status)
}

func TestWithUserAgentHeaders(t *testing.T) {
	t.Parallel()

	headers := make(chan http.Header, 1)
	client, err := retriable.New(retriable.ClientConfig{Host: "https://api.test"},
		retriable.WithTransport(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			headers <- r.Header.Clone()
			return testResponse(r, http.StatusOK, io.NopCloser(strings.NewReader(`{}`)), nil), nil
		})),
		retriable.WithUserAgent("test-agent"),
	)
	require.NoError(t, err)

	var res map[string]any
	_, _, err = client.Get(context.Background(), "/", &res)
	require.NoError(t, err)
	h := <-headers

	assert.Equal(t, []string{"test-agent"}, h.Values(header.UserAgent))
	if hostname, err := os.Hostname(); err == nil {
		assert.Equal(t, []string{hostname}, h.Values(header.XClientHostname))
	}
	if ip, err := netutil.GetLocalIP(); err == nil {
		assert.Equal(t, []string{ip}, h.Values(header.XClientIP))
	} else {
		assert.Empty(t, h.Values(header.XClientIP))
	}
}

func TestTransportSettersCloneTransport(t *testing.T) {
	t.Parallel()

	cfg := &tls.Config{ServerName: "api.test", MinVersion: tls.VersionTLS12}
	// Clone runs the lazy HTTP/2 setup of its source, which may install a
	// TLS config with ALPN protocols; the caller's settings must not appear
	serverName := func(tr *http.Transport) string {
		if tr.TLSClientConfig == nil {
			return ""
		}
		return tr.TLSClientConfig.ServerName
	}

	supplied := &http.Transport{}
	c, err := retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(supplied),
		retriable.WithTLS(cfg),
		retriable.WithDNSServer("127.0.0.1:53"),
	)
	require.NoError(t, err)
	assert.NotSame(t, cfg, supplied.TLSClientConfig)
	assert.Empty(t, serverName(supplied))
	assert.Nil(t, supplied.DialContext)
	tr, ok := c.HTTPClient().Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotSame(t, supplied, tr)
	require.NotNil(t, tr.TLSClientConfig)
	assert.Equal(t, "api.test", tr.TLSClientConfig.ServerName)
	assert.NotNil(t, tr.DialContext)

	// http.DefaultTransport is not modified either
	def, ok := http.DefaultTransport.(*http.Transport)
	require.True(t, ok)
	c, err = retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(def),
		retriable.WithTLS(cfg),
	)
	require.NoError(t, err)
	assert.NotSame(t, def, c.HTTPClient().Transport)
	assert.NotSame(t, cfg, def.TLSClientConfig)
	assert.Empty(t, serverName(def))

	// without a transport, a pooled clone of http.DefaultTransport is installed
	c, err = retriable.New(retriable.ClientConfig{}, retriable.WithTLS(cfg))
	require.NoError(t, err)
	tr, ok = c.HTTPClient().Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotSame(t, def, tr)
	assert.Same(t, cfg, tr.TLSClientConfig)
	assert.Equal(t, 100, tr.MaxConnsPerHost)
	assert.Equal(t, 100, tr.MaxIdleConnsPerHost)
	assert.Equal(t, 100, tr.MaxIdleConns)
}

func TestTransportSettersCloseReplacedIdleConnections(t *testing.T) {
	t.Parallel()

	var open atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			open.Add(1)
		case http.StateClosed, http.StateHijacked:
			open.Add(-1)
		}
	}
	server.Start()
	defer server.Close()

	get := func(c *retriable.Client) {
		var res map[string]any
		_, _, err := c.Get(context.Background(), "/", &res)
		require.NoError(t, err)
	}

	// a transport created by WithTLS is closed when it is replaced
	client, err := retriable.New(retriable.ClientConfig{Host: server.URL}, retriable.WithTLS(nil))
	require.NoError(t, err)
	for range 5 {
		get(client)
		client.WithTLS(nil)
	}
	get(client)
	assert.Eventually(t, func() bool { return open.Load() == 1 }, 5*time.Second, 10*time.Millisecond)

	// a transport passed to WithTransport belongs to the caller
	supplied := &http.Transport{}
	defer supplied.CloseIdleConnections()
	client.WithTransport(supplied)
	assert.Eventually(t, func() bool { return open.Load() == 0 }, 5*time.Second, 10*time.Millisecond)
	get(client)
	client.WithTLS(nil)
	get(client)
	client.WithTransport(supplied)
	// the supplied transport's connection stays open, the clone's is closed
	assert.Eventually(t, func() bool { return open.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Never(t, func() bool { return open.Load() != 1 }, 100*time.Millisecond, 10*time.Millisecond)
}

func TestTransportSettersRejectOtherRoundTripper(t *testing.T) {
	t.Parallel()

	const (
		errTLS = "unable to apply TLS configuration: transport is retriable_test.roundTripperFunc, not *http.Transport"
		errDNS = "unable to apply DNS server: transport is retriable_test.roundTripperFunc, not *http.Transport"
	)
	var calls atomic.Int32
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return testResponse(r, http.StatusOK, io.NopCloser(strings.NewReader(`{}`)), nil), nil
	})
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	_, err := retriable.New(retriable.ClientConfig{}, retriable.WithTransport(rt), retriable.WithTLS(cfg))
	require.EqualError(t, err, errTLS)
	_, err = retriable.New(retriable.ClientConfig{}, retriable.WithTransport(rt), retriable.WithDNSServer("127.0.0.1:53"))
	require.EqualError(t, err, errDNS)

	// WithTransport replaces the transport and clears the error
	c, err := retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(rt),
		retriable.WithTLS(cfg),
		retriable.WithTransport(rt),
	)
	require.NoError(t, err)

	// after New, requests fail closed until WithTransport replaces the transport
	c.WithTLS(cfg)
	body := newTrackingBody("{}")
	req, err := http.NewRequest(http.MethodPost, "https://api.test/", body)
	require.NoError(t, err)
	_, err = c.Do(req)
	require.EqualError(t, err, errTLS)
	assert.True(t, body.closed.Load())
	_, _, err = c.Request(context.Background(), http.MethodGet, "https://api.test", "/", nil, nil)
	require.EqualError(t, err, errTLS)
	assert.Zero(t, calls.Load())

	c.WithTransport(rt)
	req, err = http.NewRequest(http.MethodGet, "https://api.test/", nil)
	require.NoError(t, err)
	resp, err := c.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, int32(1), calls.Load())
}

func TestTransportSettersWithoutHTTPDefaultTransport(t *testing.T) {
	// not parallel: replaces http.DefaultTransport while no parallel test runs
	prev := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = prev })
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected request")
	})

	_, err := retriable.New(retriable.ClientConfig{}, retriable.WithTLS(nil))
	require.EqualError(t, err, "unable to apply TLS configuration: http.DefaultTransport is retriable_test.roundTripperFunc, not *http.Transport; set a transport with WithTransport")

	// a transport set with WithTransport does not use it
	c, err := retriable.New(retriable.ClientConfig{},
		retriable.WithTransport(&http.Transport{}),
		retriable.WithTLS(nil),
	)
	require.NoError(t, err)
	assert.IsType(t, &http.Transport{}, c.HTTPClient().Transport)
}

func TestTransportSettersDuringRequests(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	client, err := retriable.Default(server.URL)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 20 {
				var res map[string]any
				_, _, err := client.Get(context.Background(), "/", &res)
				assert.NoError(t, err)
			}
		})
	}
	wg.Go(func() {
		for range 20 {
			client.WithTLS(nil)
			client.WithDNSServer("127.0.0.1:53")
			client.WithTransport(nil)
			client.WithTimeout(time.Minute)
		}
	})
	wg.Wait()
}
