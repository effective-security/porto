package identity

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/header"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type trustedProxiesKey struct{}

// forwarding is the context value stored under trustedProxiesKey: the trust
// policy and, once NewTrustedProxyHandler has resolved it, the client IP for
// the socket address peer.
type forwarding struct {
	trust    *TrustedProxies
	peer     string
	clientIP string
	resolved bool
}

func forwardingFromContext(ctx context.Context) forwarding {
	fwd, _ := ctx.Value(trustedProxiesKey{}).(forwarding)
	return fwd
}

// TrustedProxies is an immutable set of proxy networks allowed to supply
// forwarding headers. An empty or nil set trusts no proxy.
type TrustedProxies struct {
	prefixes []netip.Prefix
}

// ParseTrustedProxies validates CIDR ranges for immediate and intermediate proxies.
func ParseTrustedProxies(cidrs []string) (*TrustedProxies, error) {
	trust := &TrustedProxies{prefixes: make([]netip.Prefix, 0, len(cidrs))}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid trusted proxy CIDR %q", cidr)
		}
		trust.prefixes = append(trust.prefixes, prefix.Masked())
	}
	return trust, nil
}

// WithTrustedProxies returns a context that uses trust when resolving proxy
// headers. It replaces any policy, and any client IP cached by
// NewTrustedProxyHandler, already in ctx.
func WithTrustedProxies(ctx context.Context, trust *TrustedProxies) context.Context {
	return context.WithValue(ctx, trustedProxiesKey{}, forwarding{trust: trust})
}

// NewTrustedProxyHandler stores trust in each request's context and resolves
// the client IP once, so that ClientIPFromRequest in later handlers (rate
// limiter, identity, request logger) returns the cached value instead of
// walking the forwarding headers again. Later changes to those headers do not
// change the cached IP; a request whose RemoteAddr differs from the one seen
// here is resolved again.
func NewTrustedProxyHandler(next http.Handler, trust *TrustedProxies) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fwd := forwarding{
			trust:    trust,
			peer:     r.RemoteAddr,
			clientIP: trust.clientIPFromRequest(r),
			resolved: true,
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), trustedProxiesKey{}, fwd)))
	})
}

// contains reports whether addr belongs to a trusted proxy network; a nil
// receiver trusts nothing. An IPv6 zone (fe80::1%eth0) is ignored, because
// netip.Prefix.Contains never matches a zoned address.
func (t *TrustedProxies) contains(addr netip.Addr) bool {
	if t == nil {
		return false
	}
	addr = addr.WithZone("")
	unmapped := addr.Unmap()
	for _, prefix := range t.prefixes {
		if prefix.Contains(unmapped) || prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func peerHost(address string) string {
	if host, _, err := net.SplitHostPort(address); err == nil {
		return host
	}
	return address
}

// trustedPeer reports whether the host of a host:port socket address is a
// trusted proxy according to trust.
func trustedPeer(trust *TrustedProxies, address string) bool {
	addr, err := netip.ParseAddr(peerHost(address))
	return err == nil && trust.contains(addr)
}

// forwardedClient resolves the client IP for a connection from peerAddress
// that carried the X-Forwarded-For values and X-Real-Ip realIP. It returns ""
// when peerAddress is empty.
func (t *TrustedProxies) forwardedClient(peerAddress string, values []string, realIP string) string {
	peerIP := peerHost(peerAddress)
	peerAddr, err := netip.ParseAddr(peerIP)
	if err != nil {
		return peerIP
	}
	peerIP = peerAddr.Unmap().String()
	if !t.contains(peerAddr) {
		return peerIP
	}

	// Walk from the socket towards the client. Addresses to the left of the
	// first untrusted hop may have been supplied by that hop. When every hop
	// is trusted, the leftmost entry was recorded by a trusted proxy and is
	// the client.
	var client netip.Addr
	for i := len(values) - 1; i >= 0; i-- {
		parts := strings.Split(values[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			addr, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
			if err != nil {
				return peerIP
			}
			client = addr.Unmap()
			if !t.contains(addr) {
				return client.String()
			}
		}
	}
	if client.IsValid() {
		return client.String()
	}
	if candidate := strings.TrimSpace(realIP); candidate != "" {
		if addr, err := netip.ParseAddr(candidate); err == nil {
			return addr.Unmap().String()
		}
	}
	return peerIP
}

// clientIPFromRequest resolves r's client IP under t without reading the
// cached value in r's context.
func (t *TrustedProxies) clientIPFromRequest(r *http.Request) string {
	return t.forwardedClient(r.RemoteAddr, r.Header.Values(header.XForwardedFor), r.Header.Get(header.XRealIP))
}

// ClientIPFromRequest returns the socket peer's IP unless that peer is in
// the request context's TrustedProxies. It then walks X-Forwarded-For from
// right to left and returns the first untrusted address, or the leftmost
// address when every hop is trusted. Invalid forwarding data falls back to
// the socket peer. A request without a RemoteAddr (for example one built with
// http.NewRequest and served in process) has no client IP and returns "".
// Behind NewTrustedProxyHandler it returns the IP resolved there.
func ClientIPFromRequest(r *http.Request) string {
	fwd := forwardingFromContext(r.Context())
	if fwd.resolved && fwd.peer == r.RemoteAddr {
		return fwd.clientIP
	}
	return fwd.trust.clientIPFromRequest(r)
}

// ForwardedProto returns a trusted proxy's http or https scheme, or an empty
// string when the peer or header is untrusted or invalid.
func ForwardedProto(r *http.Request) string {
	if !trustedPeer(forwardingFromContext(r.Context()).trust, r.RemoteAddr) {
		return ""
	}
	values := r.Header.Values(header.XForwardedProto)
	if len(values) != 1 {
		return ""
	}
	proto := values[0]
	if proto == "http" || proto == "https" {
		return proto
	}
	return ""
}

// ClientIPFromGRPC returns the peer IP unless it is a trusted proxy; trusted
// peers may supply x-forwarded-for or x-real-ip metadata. Unknown peers
// return an empty string.
func ClientIPFromGRPC(ctx context.Context) string {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo.Addr == nil {
		return ""
	}
	md, _ := metadata.FromIncomingContext(ctx)
	return forwardingFromContext(ctx).trust.forwardedClient(peerInfo.Addr.String(), md.Get(header.XForwardedFor), getMdHeader(md, header.XRealIP))
}
