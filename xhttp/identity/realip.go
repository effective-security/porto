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

// ClientIPFromRequest return client's real public IP address from http request headers.
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
		isPrivate, err := netutil.IsPrivateAddress(address)
		if !isPrivate && err == nil {
			return address
		}
	}

	// If nothing succeed, return X-Real-IP
	return xRealIP
}

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
