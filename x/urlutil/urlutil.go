package urlutil

import (
	"net/http"
	"net/url"

	"github.com/effective-security/porto/xhttp/header"
)

// GetQueryString returns Query parameter
func GetQueryString(u *url.URL, name string) string {
	vals, ok := u.Query()[name]
	if !ok || len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// GetValue returns a Query parameter
func GetValue(vals url.Values, name string) string {
	v, ok := vals[name]
	if !ok || len(v) == 0 {
		return ""
	}
	return v[0]
}

// GetPublicEndpointURL returns complete server URL for given relative end-point
func GetPublicEndpointURL(r *http.Request, relativeEndpoint string) *url.URL {
	proto := r.URL.Scheme

	// Allow upstream proxies  to specify the forwarded protocol. Allow this value
	// to override our own guess.
	if specifiedProto := r.Header.Get(header.XForwardedProto); specifiedProto != "" {
		proto = specifiedProto
	}

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if proto == "" {
		proto = "https"
	}

	return &url.URL{
		Scheme: proto,
		Host:   host,
		Path:   relativeEndpoint,
	}
}
