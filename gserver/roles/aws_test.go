package roles

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cockroachdb/errors"
	tcredentials "github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/x/values"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAWSAccount = "123456789012"
	testAWSArn     = "arn:aws:sts::123456789012:assumed-role/ci/session"
	testAWSSubject = "123456789012:assumed-role/ci"
	testAWSBody    = `{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/ci/session","UserId":"AROA:session"},"ResponseMetadata":{"RequestId":"r1"}}}`
)

// stsTransport counts STS requests and answers them with respond.
type stsTransport struct {
	calls   atomic.Int32
	respond func(*http.Request) (*http.Response, error)
}

func (s *stsTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls.Add(1)
	return s.respond(r)
}

// stsResponse answers every request with status and body.
func stsResponse(status int, body string) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	}
}

// newAWSProvider returns an AWS-enabled provider whose STS lookups go to rt.
func newAWSProvider(t *testing.T, rt http.RoundTripper) *provider {
	t.Helper()
	prov, err := New(&IdentityMap{
		AWS: AWSIdentityMap{
			Enabled:                  true,
			DefaultAuthenticatedRole: AWSUserRoleName,
			Roles: map[string][]string{
				"deployer": {testAWSSubject},
			},
		},
	}, nil)
	require.NoError(t, err)
	p := prov.(*provider)
	p.sts = &http.Client{Transport: rt, Timeout: 5 * time.Second}
	return p
}

// awsToken returns an AWS4 token for a presigned URL that expires in 15
// minutes; signature makes the URL distinct.
func awsToken(signature string) (token, presignedURL string) {
	presignedURL = "https://sts.us-west-2.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" +
		"&X-Amz-Date=" + tcredentials.TimeISO8601(time.Now().UTC()) +
		"&X-Amz-Expires=900&X-Amz-Signature=" + signature
	return base64.RawURLEncoding.EncodeToString([]byte(presignedURL)), presignedURL
}

func TestAWSIdentityCachesSuccess(t *testing.T) {
	t.Parallel()

	sts := &stsTransport{respond: func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "sts.us-west-2.amazonaws.com", r.URL.Host)
		assert.Equal(t, header.ApplicationJSON, r.Header.Get(header.Accept))
		return stsResponse(http.StatusOK, testAWSBody)(r)
	}}
	p := newAWSProvider(t, sts)
	token, _ := awsToken("good")

	for range 2 {
		r, err := http.NewRequest(http.MethodGet, "/", nil)
		require.NoError(t, err)
		r.Header.Set(header.Authorization, awsTokenType+" "+token)
		id, err := p.IdentityFromRequest(r)
		require.NoError(t, err)
		assert.Equal(t, "deployer", id.Role())
		assert.Equal(t, testAWSSubject, id.Subject())
		assert.Equal(t, testAWSAccount, id.Tenant())
		assert.Equal(t, identity.MethodAWS, id.AuthMethod())
		assert.Equal(t, testAWSArn, id.Claims()["aws_arn"])
	}
	assert.Equal(t, int32(1), sts.calls.Load())
}

// TestAWSIdentitySuccessExpires runs in a synctest bubble, which also checks
// that New starts no goroutine that outlives the provider's use: synctest.Test
// panics with "blocked goroutines remain" when one is left (the cleanup
// goroutine of the expirable LRU used before, formerly P-086), which fails
// the whole test binary.
func TestAWSIdentitySuccessExpires(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		sts := &stsTransport{respond: stsResponse(http.StatusOK, testAWSBody)}
		p := newAWSProvider(t, sts)
		token, _ := awsToken("expiring")
		lookup := func() {
			t.Helper()
			id, err := p.awsIdentity(t.Context(), token, awsTokenType)
			require.NoError(t, err)
			assert.Equal(t, "deployer", id.Role())
		}

		lookup()
		time.Sleep(tcredentials.CacheTTL - time.Second)
		lookup()
		assert.Equal(t, int32(1), sts.calls.Load(), "a success is cached for CacheTTL")

		time.Sleep(2 * time.Second)
		lookup()
		assert.Equal(t, int32(2), sts.calls.Load(), "an expired success makes a new lookup")
		lookup()
		assert.Equal(t, int32(2), sts.calls.Load(), "the new lookup is cached")
	})
}

// TestAWSIdentitySuccessWithoutTTL checks that a CacheTTL that is not
// positive keeps successes until they are evicted, as the expirable LRU did.
func TestAWSIdentitySuccessWithoutTTL(t *testing.T) {
	t.Parallel()

	for _, ttl := range []time.Duration{0, -time.Second} {
		sts := &stsTransport{respond: stsResponse(http.StatusOK, testAWSBody)}
		p := newAWSProvider(t, sts)
		p.awsTTL = ttl
		token, presignedURL := awsToken("no-ttl")
		for range 3 {
			id, err := p.awsIdentity(t.Context(), token, awsTokenType)
			require.NoError(t, err)
			assert.Equal(t, "deployer", id.Role())
		}
		assert.Equal(t, int32(1), sts.calls.Load(), ttl)
		s, ok := p.awsCache.Get(presignedURL)
		require.True(t, ok)
		assert.True(t, s.expires.IsZero(), ttl)
	}
}

func TestAWSIdentityFailureCache(t *testing.T) {
	t.Parallel()

	errNetwork := errors.New("connection reset")
	for _, tc := range []struct {
		name    string
		respond func(*http.Request) (*http.Response, error)
		err     string
		cached  bool
	}{
		{
			name:    "bad_request",
			respond: stsResponse(http.StatusBadRequest, `{"Error":{"Code":"InvalidParameterValue"}}`),
			err:     "failed to get Caller Identity from AWS: 400 Bad Request",
			cached:  true,
		},
		{
			name:    "forbidden",
			respond: stsResponse(http.StatusForbidden, `{"Error":{"Code":"SignatureDoesNotMatch"}}`),
			err:     "failed to get Caller Identity from AWS: 403 Forbidden",
			cached:  true,
		},
		{
			name:    "forbidden_xml",
			respond: stsResponse(http.StatusForbidden, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>`),
			err:     "failed to get Caller Identity from AWS: 403 Forbidden",
			cached:  true,
		},
		{
			name:    "forbidden_without_body",
			respond: stsResponse(http.StatusForbidden, ""),
			err:     "failed to get Caller Identity from AWS: 403 Forbidden",
			cached:  true,
		},
		{
			name:    "undecodable_body",
			respond: stsResponse(http.StatusOK, "not json"),
			err:     "failed to decode AWS response: invalid character 'o' in literal null (expecting 'u')",
			cached:  true,
		},
		{
			name:    "throttling",
			respond: stsResponse(http.StatusBadRequest, `{"Error":{"Code":"Throttling","Message":"Rate exceeded","Type":"Sender"}}`),
			err:     "failed to get Caller Identity from AWS: 400 Bad Request",
		},
		{
			name:    "throttling_xml",
			respond: stsResponse(http.StatusBadRequest, `<ErrorResponse><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>`),
			err:     "failed to get Caller Identity from AWS: 400 Bad Request",
		},
		{
			name:    "throttling_exception",
			respond: stsResponse(http.StatusBadRequest, `{"Error":{"Code":"ThrottlingException"}}`),
			err:     "failed to get Caller Identity from AWS: 400 Bad Request",
		},
		{
			name:    "request_timeout",
			respond: stsResponse(http.StatusRequestTimeout, ""),
			err:     "failed to get Caller Identity from AWS: 408 Request Timeout",
		},
		{
			name:    "too_many_requests",
			respond: stsResponse(http.StatusTooManyRequests, ""),
			err:     "failed to get Caller Identity from AWS: 429 Too Many Requests",
		},
		{
			name:    "server_error",
			respond: stsResponse(http.StatusInternalServerError, ""),
			err:     "failed to get Caller Identity from AWS: 500 Internal Server Error",
		},
		{
			name:    "unavailable",
			respond: stsResponse(http.StatusServiceUnavailable, ""),
			err:     "failed to get Caller Identity from AWS: 503 Service Unavailable",
		},
		{
			name: "transport_error",
			respond: func(*http.Request) (*http.Response, error) {
				return nil, errNetwork
			},
			// the presigned URL in the *url.Error text is dropped
			err: "unable to get Caller Identity from AWS host sts.us-west-2.amazonaws.com: connection reset",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sts := &stsTransport{respond: tc.respond}
			p := newAWSProvider(t, sts)
			token, _ := awsToken("bad-signature")

			_, err := p.awsIdentity(context.Background(), token, awsTokenType)
			require.EqualError(t, err, tc.err)
			assert.NotContains(t, fmt.Sprintf("%+v", err), "bad-signature")

			_, err = p.awsIdentity(context.Background(), token, awsTokenType)
			if tc.cached {
				require.EqualError(t, err, "cached STS lookup failure: "+tc.err)
				assert.Equal(t, int32(1), sts.calls.Load())
			} else {
				require.EqualError(t, err, tc.err)
				assert.Equal(t, int32(2), sts.calls.Load())
			}

			// another presigned URL is looked up
			other, _ := awsToken("other")
			_, err = p.awsIdentity(context.Background(), other, awsTokenType)
			require.EqualError(t, err, tc.err)
			assert.Equal(t, values.Select(tc.cached, int32(2), int32(3)), sts.calls.Load())
		})
	}
}

func TestCacheableSTSFailure(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status int
		body   string
		exp    bool
	}{
		{status: 302},
		{status: 399},
		{status: 400, exp: true},
		{status: 400, body: `{"Error":{"Code":"Throttling"}}`},
		{status: 400, body: `{"Error":{"Code":"RequestLimitExceeded"}}`},
		{status: 400, body: `<ErrorResponse><Error><Code>ThrottlingException</Code></Error></ErrorResponse>`},
		{status: 403, body: `{"Error":{"Code":"InvalidClientTokenId"}}`, exp: true},
		{status: 403, body: "<html>", exp: true},
		{status: 408},
		{status: 429},
		{status: 499, exp: true},
		{status: 500},
		{status: 503, body: `{"Error":{"Code":"SignatureDoesNotMatch"}}`},
	} {
		assert.Equal(t, tc.exp, cacheableSTSFailure(tc.status, []byte(tc.body)), "%d %s", tc.status, tc.body)
	}
}

func TestSTSErrorCode(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		body string
		exp  string
	}{
		{body: `{"Error":{"Code":"Throttling","Message":"Rate exceeded","Type":"Sender"},"RequestId":"r1"}`, exp: "Throttling"},
		{body: `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Code>ExpiredToken</Code></Error></ErrorResponse>`, exp: "ExpiredToken"},
		{body: `{"Error":{}}`},
		{body: "not a response"},
		{body: ""},
	} {
		assert.Equal(t, tc.exp, stsErrorCode([]byte(tc.body)), tc.body)
	}
}

func TestAWSIdentityFailureExpires(t *testing.T) {
	t.Parallel()

	var status atomic.Int32
	status.Store(http.StatusForbidden)
	sts := &stsTransport{respond: func(r *http.Request) (*http.Response, error) {
		return stsResponse(int(status.Load()), testAWSBody)(r)
	}}
	p := newAWSProvider(t, sts)
	token, presignedURL := awsToken("later-valid")

	_, err := p.awsIdentity(context.Background(), token, awsTokenType)
	require.EqualError(t, err, "failed to get Caller Identity from AWS: 403 Forbidden")
	f, ok := p.awsFailures.Get(presignedURL)
	require.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(awsFailureTTL), f.expires, 5*time.Second)

	// expire the cached failure
	f.expires = time.Now().Add(-time.Second)
	p.awsFailures.Add(presignedURL, f)
	status.Store(http.StatusOK)

	id, err := p.awsIdentity(context.Background(), token, awsTokenType)
	require.NoError(t, err)
	assert.Equal(t, "deployer", id.Role())
	assert.Equal(t, int32(2), sts.calls.Load())

	// the success is cached ahead of the stale failure
	_, err = p.awsIdentity(context.Background(), token, awsTokenType)
	require.NoError(t, err)
	assert.Equal(t, int32(2), sts.calls.Load())
}

func TestAWSIdentityFailuresKeepSuccesses(t *testing.T) {
	t.Parallel()

	good, _ := awsToken("good")
	goodSig := "X-Amz-Signature=good"
	sts := &stsTransport{respond: func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.RawQuery, goodSig) {
			return stsResponse(http.StatusOK, testAWSBody)(r)
		}
		return stsResponse(http.StatusForbidden, "")(r)
	}}
	p := newAWSProvider(t, sts)

	_, err := p.awsIdentity(context.Background(), good, awsTokenType)
	require.NoError(t, err)
	const failures = 2 * awsCacheSize
	for i := range failures {
		bad, _ := awsToken(fmt.Sprintf("bad-%d", i))
		_, err := p.awsIdentity(context.Background(), bad, awsTokenType)
		require.Error(t, err)
	}
	assert.Equal(t, int32(1+failures), sts.calls.Load())
	assert.Equal(t, awsCacheSize, p.awsFailures.Len())

	// failures fill their own cache, not the one of successful lookups
	_, err = p.awsIdentity(context.Background(), good, awsTokenType)
	require.NoError(t, err)
	assert.Equal(t, int32(1+failures), sts.calls.Load())
}

// doneSignalContext closes entered the first time Done is called, which a
// waiter does only once it waits for the shared lookup.
type doneSignalContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (ctx *doneSignalContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.entered) })
	return ctx.Context.Done()
}

func newDoneSignalContext(ctx context.Context) *doneSignalContext {
	return &doneSignalContext{Context: ctx, entered: make(chan struct{})}
}

// blockingSTS answers each request once release is closed, with fail's
// panic or error when set and testAWSBody otherwise, or with the request's
// context error if that ends first. started is closed when the first
// request arrives.
type blockingSTS struct {
	stsTransport
	started chan struct{}
	release chan struct{}
	once    sync.Once
	panics  atomic.Bool
}

func newBlockingSTS() *blockingSTS {
	b := &blockingSTS{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	b.respond = func(r *http.Request) (*http.Response, error) {
		b.once.Do(func() { close(b.started) })
		select {
		case <-b.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		if b.panics.Load() {
			panic("transport failure")
		}
		return stsResponse(http.StatusOK, testAWSBody)(r)
	}
	return b
}

// startAWSIdentity runs awsIdentity with ctx and returns its error channel.
func startAWSIdentity(p *provider, ctx context.Context, token string) chan error {
	res := make(chan error, 1)
	go func() {
		id, err := p.awsIdentity(ctx, token, awsTokenType)
		if err == nil && id.Role() != "deployer" {
			err = errors.Newf("unexpected role %q", id.Role())
		}
		res <- err
	}()
	return res
}

func TestAWSIdentitySharedLookup(t *testing.T) {
	t.Parallel()

	sts := newBlockingSTS()
	p := newAWSProvider(t, sts)
	token, _ := awsToken("shared")

	const waiters = 7
	results := []chan error{startAWSIdentity(p, context.Background(), token)}
	<-sts.started
	for range waiters {
		ctx := newDoneSignalContext(context.Background())
		results = append(results, startAWSIdentity(p, ctx, token))
		<-ctx.entered
	}
	assert.Equal(t, int32(1), sts.calls.Load())

	close(sts.release)
	for _, res := range results {
		require.NoError(t, <-res)
	}
	assert.Equal(t, int32(1), sts.calls.Load())
}

func TestAWSIdentityWaiterCanceled(t *testing.T) {
	t.Parallel()

	sts := newBlockingSTS()
	p := newAWSProvider(t, sts)
	token, _ := awsToken("waiter-canceled")

	first := startAWSIdentity(p, context.Background(), token)
	<-sts.started
	ctx, cancel := context.WithCancel(context.Background())
	waiterCtx := newDoneSignalContext(ctx)
	waiter := startAWSIdentity(p, waiterCtx, token)
	<-waiterCtx.entered

	cancel()
	err := <-waiter
	require.ErrorIs(t, err, context.Canceled)
	assert.EqualError(t, err, "unable to get Caller Identity from AWS: context canceled")

	close(sts.release)
	require.NoError(t, <-first)
	assert.Equal(t, int32(1), sts.calls.Load())
}

func TestAWSIdentityLeaderCanceled(t *testing.T) {
	t.Parallel()

	sts := newBlockingSTS()
	p := newAWSProvider(t, sts)
	token, presignedURL := awsToken("leader-canceled")

	// the request that makes the lookup goes away, which ends the lookup
	ctx, cancel := context.WithCancel(context.Background())
	first := startAWSIdentity(p, ctx, token)
	<-sts.started
	waiterCtx := newDoneSignalContext(context.Background())
	waiter := startAWSIdentity(p, waiterCtx, token)
	<-waiterCtx.entered

	cancel()
	err := <-first
	require.ErrorIs(t, err, context.Canceled)
	assert.EqualError(t, err, "unable to get Caller Identity from AWS host sts.us-west-2.amazonaws.com: context canceled")
	_, ok := p.awsFailures.Get(presignedURL)
	assert.False(t, ok)

	// the live waiter makes the next lookup
	close(sts.release)
	require.NoError(t, <-waiter)
	assert.Equal(t, int32(2), sts.calls.Load())
}

func TestAWSIdentityLookupPanic(t *testing.T) {
	t.Parallel()

	sts := newBlockingSTS()
	sts.panics.Store(true)
	p := newAWSProvider(t, sts)
	token, _ := awsToken("panic")

	leader := make(chan any, 1)
	go func() {
		defer func() { leader <- recover() }()
		_, _ = p.awsIdentity(context.Background(), token, awsTokenType)
	}()
	<-sts.started
	waiterCtx := newDoneSignalContext(context.Background())
	waiter := startAWSIdentity(p, waiterCtx, token)
	<-waiterCtx.entered

	close(sts.release)
	// the panic reaches the request that made the lookup
	assert.Equal(t, "transport failure", <-leader)
	require.EqualError(t, <-waiter, "STS lookup panicked")

	// the next request looks up again instead of waiting forever
	sts.panics.Store(false)
	require.NoError(t, <-startAWSIdentity(p, context.Background(), token))
	assert.Equal(t, int32(2), sts.calls.Load())
}

func TestSTSURLErrorsOmitURL(t *testing.T) {
	t.Parallel()

	const bad = "https://sts.amazonaws.com/%zz?Action=GetCallerIdentity&X-Amz-Signature=secret-signature"
	_, _, _, err := ParseSTSTokenExpiration(bad)
	require.EqualError(t, err, `failed to parse presigned URL: invalid URL escape "%zz"`)
	assert.NotContains(t, fmt.Sprintf("%+v", err), "secret-signature")

	err = ValidateSTSPresignedURL(bad)
	require.EqualError(t, err, `failed to parse presigned URL: invalid URL escape "%zz"`)
	assert.NotContains(t, fmt.Sprintf("%+v", err), "secret-signature")
}
