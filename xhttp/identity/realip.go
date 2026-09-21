package identity

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/effective-security/x/netutil"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// ClientIPFromRequest returns the client's IP address as a string. When the
// X-Real-Ip and X-Forwarded-For headers are both absent it is the host part
// of r.RemoteAddr (or the local IP if that is empty). Otherwise it is the
// first globally routable address in X-Forwarded-For, falling back to
// X-Real-Ip (which may be ""). The headers are trusted as sent, so the
// result is only reliable behind a proxy that overwrites them.
func ClientIPFromRequest(r *http.Request) string {
	// Fetch header value
	xRealIP := r.Header.Get("X-Real-Ip")
	xForwardedFor := r.Header.Get("X-Forwarded-For")

	// If both empty, return IP from remote address
	if xRealIP == "" && xForwardedFor == "" {
		var remoteIP string

		// If there are colon in remote address, remove the port number
		// otherwise, return remote address as is
		if strings.ContainsRune(r.RemoteAddr, ':') {
			remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		} else {
			remoteIP = r.RemoteAddr
		}

		if remoteIP == "" {
			remoteIP, _ = netutil.GetLocalIP()
		}
		return remoteIP
	}

	// Check list of IP in X-Forwarded-For and return the first global address
	for _, address := range strings.Split(xForwardedFor, ",") {
		address = strings.TrimSpace(address)
		if ip := net.ParseIP(address); ip != nil && !isPrivateIP(ip) {
			return address
		}
	}

	// If nothing succeed, return X-Real-IP
	return xRealIP
}

// ClientIPFromGRPC returns the client address for a gRPC call: the raw value
// of the x-forwarded-for or x-real-ip incoming metadata when present,
// otherwise the peer address including port, or "" when unknown.
func ClientIPFromGRPC(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		vals := md.Get("x-forwarded-for")
		if len(vals) > 0 {
			return vals[0]
		}
		vals = md.Get("x-real-ip")
		if len(vals) > 0 {
			return vals[0]
		}
	}

	peerInfo, ok := peer.FromContext(ctx)
	if ok {
		return peerInfo.Addr.String()
	}
	return ""
}

// isPrivateIP reports whether ip is not globally routable: RFC 1918 / ULA
// private ranges, loopback, or link-local unicast. Such addresses in an
// X-Forwarded-For chain belong to proxies rather than the originating client.
func isPrivateIP(ip net.IP) bool {
	// TODO: consider:
	// return !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
