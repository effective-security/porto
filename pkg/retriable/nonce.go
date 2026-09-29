package retriable

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xlog"
)

const (
	// DefaultReplayNonceHeader is the conventional (ACME-style) header name
	// carrying a replay nonce; pass it to Client.WithNonce or NewNonceProvider.
	DefaultReplayNonceHeader = header.ReplayNonce
)

// NonceProvider supplies server-issued replay nonces for signed requests.
// It satisfies jose.NonceSource.
type NonceProvider interface {
	// Nonce returns an unused nonce, taking a cached one received in an
	// earlier response or fetching a fresh one from the server.
	// It implements jose.NonceSource, which passes no context; the default
	// provider bounds the fetch with a 30s timeout. Use NonceContext when a
	// context is available.
	Nonce() (string, error)
	// NonceContext is Nonce with the fetch bounded by ctx.
	NonceContext(ctx context.Context) (string, error)
	// SetFromHeader caches the nonce found in the response headers, if any.
	SetFromHeader(hdr http.Header)
}

const (
	nonceCacheLimit = 64
	// nonceFetchTimeout bounds the fetch made by Nonce, which has no context.
	nonceFetchTimeout = 30 * time.Second
)

type nonceProvider struct {
	headerName string
	noncePath  string
	nonces     []string
	lock       sync.RWMutex
	client     HTTPClient
}

// NewNonceProvider returns the default NonceProvider: it keeps a bounded
// LIFO cache (64 entries; when full, the oldest half is dropped) of nonces
// seen in headerName response headers, and when empty fetches one with a
// HEAD request to noncePath through client. It is safe for concurrent use.
func NewNonceProvider(client HTTPClient, noncePath, headerName string) NonceProvider {
	return &nonceProvider{
		client:     client,
		headerName: headerName,
		noncePath:  noncePath,
	}
}

// SetFromHeader extracts Nonce from a HTTP response headers
func (c *nonceProvider) SetFromHeader(hdr http.Header) {
	c.pushNonce(hdr.Get(c.headerName))
}

// popNonce Pops a nonce.
func (c *nonceProvider) popNonce() (string, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	count := len(c.nonces)
	if count == 0 {
		return "", false
	}

	nonce := c.nonces[count-1]
	c.nonces = c.nonces[:count-1]
	return nonce, true
}

// pushNonce Pushes a nonce.
func (c *nonceProvider) pushNonce(nonce string) {
	if nonce != "" {
		c.lock.Lock()
		defer c.lock.Unlock()

		count := len(c.nonces)
		if count >= nonceCacheLimit {
			// drop the oldest half: the newest nonces are popped first
			// and are the least likely to have expired on the server
			c.nonces = slices.Delete(c.nonces, 0, count-nonceCacheLimit/2)
		}
		c.nonces = append(c.nonces, nonce)
	}
}

// Nonce implements jose.NonceSource; a fetch is bounded by nonceFetchTimeout.
func (c *nonceProvider) Nonce() (string, error) {
	if nonce, ok := c.popNonce(); ok {
		return nonce, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), nonceFetchTimeout)
	defer cancel()
	return c.getNonce(ctx)
}

// NonceContext returns a cached nonce, or fetches one bounded by ctx.
func (c *nonceProvider) NonceContext(ctx context.Context) (string, error) {
	if nonce, ok := c.popNonce(); ok {
		return nonce, nil
	}
	return c.getNonce(ctx)
}

func (c *nonceProvider) getNonce(ctx context.Context) (string, error) {
	logger.ContextKV(ctx, xlog.DEBUG, "reason", "fetch_nonce")
	if c.noncePath == "" {
		return "", errors.New("Nonce is not configured")
	}
	hdr, _, err := c.client.Head(ctx, c.noncePath)
	if err != nil {
		return "", errors.WithMessagef(err, "failed to get nonce")
	}

	nonce := hdr.Get(c.headerName)
	if nonce == "" {
		return "", errors.New("server did not respond with a proper nonce header")
	}
	return nonce, nil
}
