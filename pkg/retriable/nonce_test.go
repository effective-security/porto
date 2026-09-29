package retriable

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Nonce(t *testing.T) {
	h := testNonceHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	client, err := Default(server.URL)
	require.NoError(t, err)
	require.NotNil(t, client)

	assert.Nil(t, client.GetNonceProvider())

	client.WithNonce(client.CurrentHost()+"/nonce", DefaultReplayNonceHeader)
	assert.NotNil(t, client.GetNonceProvider())

	client.SetNonceProvider(client.GetNonceProvider())
	assert.NotNil(t, client.GetNonceProvider())

	np := client.nonceProvider.(*nonceProvider)
	assert.Empty(t, np.nonces)

	ctx := context.Background()

	var res map[string]any
	_, _, err = client.Get(ctx, "/test", &res)
	require.NoError(t, err)
	assert.Len(t, np.nonces, 1)

	nonce, err := np.Nonce()
	require.NoError(t, err)
	assert.NotEmpty(t, nonce)
	assert.Empty(t, np.nonces)

	nonce, err = np.Nonce()
	require.NoError(t, err)
	assert.NotEmpty(t, nonce)
	assert.Empty(t, np.nonces)

	for i := 0; i < nonceCacheLimit+1; i++ {
		np.pushNonce("122")
	}
	nonce, err = np.Nonce()
	require.NoError(t, err)
	assert.NotEmpty(t, nonce)
	assert.True(t, len(np.nonces) < nonceCacheLimit-1)
}

func testNonceHandler() http.Handler {
	h := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("X-Request-URL", r.URL.String())
		w.Header().Add("X-Request-Method", r.Method)
		w.Header().Add(DefaultReplayNonceHeader, certutil.RandomString(8))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}
	return http.HandlerFunc(h)
}

// headClient is an HTTPClient whose Head records its context and returns
// the configured headers or error.
type headClient struct {
	HTTPClient

	mu   sync.Mutex
	ctxs []context.Context
	hdr  http.Header
	err  error
}

func (c *headClient) Head(ctx context.Context, _ string) (http.Header, int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctxs = append(c.ctxs, ctx)
	if c.err != nil {
		return nil, 0, c.err
	}
	return c.hdr, http.StatusOK, nil
}

func (c *headClient) contexts() []context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]context.Context(nil), c.ctxs...)
}

func TestNonceCacheKeepsNewest(t *testing.T) {
	t.Parallel()

	client := &headClient{err: errors.New("unexpected fetch")}
	np := NewNonceProvider(client, "/nonce", DefaultReplayNonceHeader)
	for i := range nonceCacheLimit + 1 {
		np.SetFromHeader(http.Header{DefaultReplayNonceHeader: {fmt.Sprintf("n%d", i)}})
	}
	// the oldest half was dropped; the newest nonce is returned first
	for i := nonceCacheLimit; i >= nonceCacheLimit/2; i-- {
		nonce, err := np.NonceContext(context.Background())
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("n%d", i), nonce)
	}
	_, err := np.NonceContext(context.Background())
	require.EqualError(t, err, "failed to get nonce: unexpected fetch")
	assert.Len(t, client.contexts(), 1)
}

func TestNonceFetchContext(t *testing.T) {
	t.Parallel()

	client := &headClient{hdr: http.Header{DefaultReplayNonceHeader: {"fresh"}}}
	np := NewNonceProvider(client, "/nonce", DefaultReplayNonceHeader)

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "caller")
	nonce, err := np.NonceContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, "fresh", nonce)

	// Nonce has no context parameter: its fetch is bounded by a timeout
	started := time.Now()
	nonce, err = np.Nonce()
	require.NoError(t, err)
	assert.Equal(t, "fresh", nonce)

	ctxs := client.contexts()
	require.Len(t, ctxs, 2)
	assert.Equal(t, "caller", ctxs[0].Value(ctxKey{}))
	deadline, ok := ctxs[1].Deadline()
	require.True(t, ok)
	assert.WithinDuration(t, started.Add(nonceFetchTimeout), deadline, time.Second)
	// released when Nonce returns
	assert.ErrorIs(t, ctxs[1].Err(), context.Canceled)
}

func TestNonceFetchErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, err := NewNonceProvider(&headClient{}, "", DefaultReplayNonceHeader).NonceContext(ctx)
	require.EqualError(t, err, "Nonce is not configured")

	_, err = NewNonceProvider(&headClient{hdr: http.Header{}}, "/nonce", DefaultReplayNonceHeader).NonceContext(ctx)
	require.EqualError(t, err, "server did not respond with a proper nonce header")
}
