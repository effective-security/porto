package gserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rateLimitRemoteAddrHeader is the tollbooth response header that echoes
// the address the limiter keyed on.
const rateLimitRemoteAddrHeader = "X-Rate-Limit-Request-Remote-Addr"

func TestDefaultRateLimitUsesTrustedClient(t *testing.T) {
	t.Parallel()
	enabled := true
	trust, err := identity.ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	for _, tt := range []struct {
		name       string
		trust      *identity.TrustedProxies
		remote     string
		firstXFF   string
		secondXFF  string
		firstKey   string
		secondKey  string
		secondCode int
	}{
		{"direct header spoof", nil, "198.51.100.7:123", "203.0.113.1", "203.0.113.2", "198.51.100.7", "198.51.100.7", http.StatusTooManyRequests},
		{"trusted same client", trust, "10.0.0.2:123", "203.0.113.1", "203.0.113.1", "203.0.113.1", "203.0.113.1", http.StatusTooManyRequests},
		{"trusted distinct clients", trust, "10.0.0.2:123", "203.0.113.1", "203.0.113.2", "203.0.113.1", "203.0.113.2", http.StatusOK},
		{"mapped IPv4 clients", trust, "10.0.0.2:123", "::ffff:203.0.113.1", "::ffff:203.0.113.2", "203.0.113.1", "203.0.113.2", http.StatusOK},
		{"IPv6 peer", nil, "[2001:db8::7]:123", "", "", "2001:db8::7", "2001:db8::7", http.StatusTooManyRequests},
		// tollbooth does not limit a request without a client IP.
		{"no peer", trust, "", "203.0.113.1", "203.0.113.1", "", "", http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var seen []*http.Request
			h := configureRateLimiter(&RateLimit{Enabled: &enabled, RequestsPerSecond: 1}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = append(seen, r)
				w.WriteHeader(http.StatusOK)
			}))
			h = identity.NewTrustedProxyHandler(h, tt.trust)
			for i, xff := range []string{tt.firstXFF, tt.secondXFF} {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = tt.remote
				if xff != "" {
					r.Header.Set(header.XForwardedFor, xff)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				wantCode, wantKey := http.StatusOK, tt.firstKey
				if i == 1 {
					wantCode, wantKey = tt.secondCode, tt.secondKey
				}
				assert.Equal(t, wantCode, w.Code)
				assert.Equal(t, wantKey, w.Header().Get(rateLimitRemoteAddrHeader))
				if wantCode == http.StatusOK {
					require.Len(t, seen, i+1)
					assert.Equal(t, tt.remote, seen[i].RemoteAddr, "handler must see the socket peer")
				}
			}
		})
	}
}

// TestDefaultRateLimitRejection checks that the default limiter answers a
// rejected request the same way tollbooth.LimitHandler does.
func TestDefaultRateLimitRejection(t *testing.T) {
	t.Parallel()
	enabled := true
	calls := 0
	h := configureRateLimiter(&RateLimit{Enabled: &enabled, RequestsPerSecond: 1}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	h = identity.NewTrustedProxyHandler(h, nil)

	codes := make([]int, 0, 2)
	var rejected *httptest.ResponseRecorder
	for range 2 {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "198.51.100.7:123"
		rejected = httptest.NewRecorder()
		h.ServeHTTP(rejected, r)
		codes = append(codes, rejected.Code)
	}
	assert.Equal(t, []int{http.StatusOK, http.StatusTooManyRequests}, codes)
	assert.Equal(t, 1, calls)
	assert.Equal(t, "text/plain; charset=utf-8", rejected.Header().Get(header.ContentType))
	assert.Equal(t, "You have reached maximum request limit.", rejected.Body.String())
}
