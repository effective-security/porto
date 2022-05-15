package urlutil_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/effective-security/porto/x/urlutil"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetQueryString(t *testing.T) {
	u, err := url.Parse("http://localhost?q=test")
	require.NoError(t, err)

	assert.Equal(t, "test", urlutil.GetQueryString(u, "q"))
	assert.Equal(t, "", urlutil.GetQueryString(u, "p"))

	vals := u.Query()
	assert.Equal(t, "test", urlutil.GetValue(vals, "q"))
	assert.Equal(t, "", urlutil.GetValue(vals, "p"))
}

func TestGetPublicServerURL(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/v1/status", nil)
	require.NoError(t, err)

	u := urlutil.GetPublicEndpointURL(r, "/v1").String()
	assert.Equal(t, "https:///v1", u)

	r.URL.Scheme = "https"
	r.Host = "martini.com:8443"
	u = urlutil.GetPublicEndpointURL(r, "/v1").String()
	assert.Equal(t, "https://martini.com:8443/v1", u)

	r.Header.Set(header.XForwardedProto, "http")
	u = urlutil.GetPublicEndpointURL(r, "/v1").String()
	assert.Equal(t, "http://martini.com:8443/v1", u)
}
