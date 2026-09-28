package identity

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestClientIPFromRequest(t *testing.T) {
	t.Parallel()
	trust, err := ParseTrustedProxies([]string{"10.0.0.0/8", "2001:db8::/32", "fe80::/10"})
	require.NoError(t, err)

	tests := []struct {
		name    string
		remote  string
		xff     []string
		realIP  string
		trusted bool
		want    string
	}{
		{"direct spoof", "198.51.100.7:123", []string{"203.0.113.9"}, "203.0.113.8", false, "198.51.100.7"},
		{"trusted single hop", "10.0.0.2:123", []string{"203.0.113.9"}, "", true, "203.0.113.9"},
		{"private only fallback", "10.0.0.2:123", []string{"192.168.1.4"}, "", true, "192.168.1.4"},
		{"multiple headers and trusted hops", "10.0.0.2:123", []string{"192.168.1.4", "10.0.0.3"}, "", true, "192.168.1.4"},
		{"all hops trusted returns leftmost", "10.0.0.2:123", []string{"10.0.0.5, 10.0.0.3"}, "", true, "10.0.0.5"},
		{"spoofed leftmost", "10.0.0.2:123", []string{"203.0.113.9, 192.168.1.4"}, "", true, "192.168.1.4"},
		{"invalid nearest hop", "10.0.0.2:123", []string{"203.0.113.9, garbage"}, "", true, "10.0.0.2"},
		{"real IP fallback", "10.0.0.2:123", nil, "203.0.113.8", true, "203.0.113.8"},
		{"invalid real IP", "10.0.0.2:123", nil, "bad", true, "10.0.0.2"},
		{"ipv6", "[2001:db8::2]:123", []string{"2001:4860::1"}, "", true, "2001:4860::1"},
		{"mapped ipv4 peer", "[::ffff:198.51.100.7]:123", []string{"203.0.113.9"}, "", false, "198.51.100.7"},
		{"mapped ipv4 forwarded", "10.0.0.2:123", []string{"::ffff:203.0.113.9"}, "", true, "203.0.113.9"},
		{"zoned ipv6 peer", "[fe80::1%eth0]:123", []string{"203.0.113.9"}, "", true, "203.0.113.9"},
		{"zoned ipv6 hop", "10.0.0.2:123", []string{"203.0.113.9, fe80::2%eth0"}, "", true, "203.0.113.9"},
		{"zoned ipv6 peer untrusted", "[fe80::1%eth0]:123", []string{"203.0.113.9"}, "", false, "fe80::1%eth0"},
		{"no peer", "", nil, "", false, ""},
		{"no peer ignores forwarding headers", "", []string{"203.0.113.9"}, "203.0.113.8", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			for _, value := range tt.xff {
				r.Header.Add(header.XForwardedFor, value)
			}
			r.Header.Set(header.XRealIP, tt.realIP)
			if tt.trusted {
				r = r.WithContext(WithTrustedProxies(r.Context(), trust))
			}
			assert.Equal(t, tt.want, ClientIPFromRequest(r))
		})
	}
}

func TestNewTrustedProxyHandlerCachesClientIP(t *testing.T) {
	t.Parallel()
	trust, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	var cached, rewrittenPeer, replacedPolicy, proto string
	h := NewTrustedProxyHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Header changes after the trust boundary do not change the IP.
		r.Header.Set(header.XForwardedFor, "198.51.100.99")
		cached = ClientIPFromRequest(r)

		// A different socket peer is resolved again, with current headers.
		other := r.Clone(r.Context())
		other.RemoteAddr = "10.0.0.3:456"
		rewrittenPeer = ClientIPFromRequest(other)

		// WithTrustedProxies replaces both the policy and the cached IP.
		replacedPolicy = ClientIPFromRequest(r.WithContext(WithTrustedProxies(r.Context(), nil)))

		proto = ForwardedProto(r)
	}), trust)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.2:123"
	r.Header.Set(header.XForwardedFor, "203.0.113.9")
	r.Header.Set(header.XForwardedProto, "https")
	h.ServeHTTP(httptest.NewRecorder(), r)

	assert.Equal(t, "203.0.113.9", cached)
	assert.Equal(t, "198.51.100.99", rewrittenPeer)
	assert.Equal(t, "10.0.0.2", replacedPolicy)
	assert.Equal(t, "https", proto)
	// The caller's request context has no policy, so its peer is the client.
	assert.Equal(t, "10.0.0.2", ClientIPFromRequest(r))
}

func TestForwardedProto(t *testing.T) {
	t.Parallel()
	trust, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.2:123"
	r.Header.Set(header.XForwardedProto, "https")
	assert.Empty(t, ForwardedProto(r))
	r = r.WithContext(WithTrustedProxies(r.Context(), trust))
	assert.Equal(t, "https", ForwardedProto(r))
	r.Header.Set(header.XForwardedProto, "https,http")
	assert.Empty(t, ForwardedProto(r))
	r.Header.Set(header.XForwardedProto, "javascript")
	assert.Empty(t, ForwardedProto(r))
	r.Header.Set(header.XForwardedProto, "https")
	r.Header.Add(header.XForwardedProto, "http")
	assert.Empty(t, ForwardedProto(r))

	zoned, err := ParseTrustedProxies([]string{"fe80::/10"})
	require.NoError(t, err)
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[fe80::1%eth0]:123"
	r.Header.Set(header.XForwardedProto, "https")
	r = r.WithContext(WithTrustedProxies(r.Context(), zoned))
	assert.Equal(t, "https", ForwardedProto(r))
}

func TestClientIPFromGRPC(t *testing.T) {
	t.Parallel()
	trust, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 123}})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-forwarded-for", "203.0.113.9, 192.168.1.4", "x-real-ip", "203.0.113.8"))
	assert.Equal(t, "10.0.0.2", ClientIPFromGRPC(ctx))
	assert.Equal(t, "192.168.1.4", ClientIPFromGRPC(WithTrustedProxies(ctx, trust)))
	assert.Empty(t, ClientIPFromGRPC(metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-forwarded-for", "203.0.113.9"))))

	zoned, err := ParseTrustedProxies([]string{"fe80::/10"})
	require.NoError(t, err)
	ctx = peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 123, Zone: "eth0"}})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-forwarded-for", "203.0.113.9"))
	assert.Equal(t, "203.0.113.9", ClientIPFromGRPC(WithTrustedProxies(ctx, zoned)))
}

func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()
	_, err := ParseTrustedProxies([]string{"bad"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "invalid trusted proxy CIDR"))
}
