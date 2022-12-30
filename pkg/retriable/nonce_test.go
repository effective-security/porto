package retriable

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Nonce(t *testing.T) {
	h := testNonceHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	client := New().WithHosts([]string{server.URL})
	client.NonceProvider = NewNonceProvider(client, "/nonce", DefaultReplayNonceHeader)

	np := client.NonceProvider.(*nonceProvider)
	assert.Empty(t, np.nonces)

	ctx := context.Background()

	var res map[string]interface{}
	_, _, err := client.Get(ctx, "/test", &res)
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
