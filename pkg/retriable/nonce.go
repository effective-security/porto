package retriable

import (
	"context"
	"net/http"
	"sync"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

const (
	// DefaultReplayNonceHeader provides header name for nonce
	DefaultReplayNonceHeader = "Replay-Nonce"
)

// NonceProvider specifies interface for Nonces
type NonceProvider interface {
	// Nonce returns new nonce by fetching from server
	Nonce() (string, error)
	// SetFromHeader extracts Nonce from a HTTP response headers
	SetFromHeader(hdr http.Header)
}

const nonceCacheLimit = 64

type nonceProvider struct {
	headerName string
	noncePath  string
	nonces     []string
	lock       sync.RWMutex
	client     HTTPClient
}

// NewNonceProvider returns default nonce provider
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
			c.nonces = c.nonces[nonceCacheLimit/2 : count-1]
		}
		c.nonces = append(c.nonces, nonce)
	}
}

// Nonce implement jose.NonceSource.
func (c *nonceProvider) Nonce() (string, error) {
	if nonce, ok := c.popNonce(); ok {
		return nonce, nil
	}
	logger.KV(xlog.DEBUG, "reason", "fetch_nonce")
	return c.getNonce(context.Background())
}

func (c *nonceProvider) getNonce(ctx context.Context) (string, error) {
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
