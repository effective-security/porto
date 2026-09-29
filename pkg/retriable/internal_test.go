package retriable

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"testing"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithUserAgentOmitsUnresolvedIP(t *testing.T) {
	// not parallel: replaces the localIP seam while no parallel test runs
	prev := localIP
	t.Cleanup(func() { localIP = prev })
	calls := 0
	localIP = func() (string, error) {
		calls++
		return "", errors.New("no network")
	}

	c, err := New(ClientConfig{}, WithUserAgent("agent"))
	require.NoError(t, err)
	assert.Equal(t, 1, calls)

	c.lock.RLock()
	headers := maps.Clone(c.headers)
	c.lock.RUnlock()
	assert.Equal(t, "agent", headers[header.UserAgent])
	_, ok := headers[header.XClientIP]
	assert.False(t, ok)
}

func Test_WithDNSServer_UsingOptions_OK(t *testing.T) {
	client, err := New(ClientConfig{}, WithTransport(http.DefaultTransport), WithDNSServer("8.8.8.8:53"))
	require.NoError(t, err)
	require.NotNil(t, client)

	tr, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	_, err = tr.DialContext(context.Background(), "tcp", "google.com:80")
	require.NoError(t, err)
}

func Test_WithDNSServer_UsingOptions_Fail(t *testing.T) {
	client, err := New(ClientConfig{}, WithTransport(http.DefaultTransport), WithDNSServer("8.8.8.8"))
	require.NoError(t, err)
	require.NotNil(t, client)

	tr, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)

	_, err = tr.DialContext(context.Background(), "udp", "google.com:80")
	require.Error(t, err)
	require.Contains(t, err.Error(), "address 8.8.8.8: missing port in address")
}

func Test_WithDNSServer_OK(t *testing.T) {
	client1, err := New(ClientConfig{}, WithTransport(http.DefaultTransport), WithDNSServer("8.8.8.8:53"))
	require.NoError(t, err)
	require.NotNil(t, client1)

	tr, ok := client1.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	_, err = tr.DialContext(context.Background(), "tcp", "google.com:80")
	require.NoError(t, err)

	client2, err := New(ClientConfig{}, WithDNSServer("8.8.8.8:53"))
	require.NotNil(t, client2)

	tr, ok = client2.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	_, err = tr.DialContext(context.Background(), "tcp", "google.com:80")
	require.NoError(t, err)
}

func Test_WithDNSServer_NoPort(t *testing.T) {
	client, err := New(ClientConfig{},
		WithTransport(http.DefaultTransport.(*http.Transport).Clone()),
		WithDNSServer("8.8.8.8"))
	require.NoError(t, err)
	require.NotNil(t, client)

	tr, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)

	_, err = tr.DialContext(context.Background(), "udp", "google.com:80")
	require.Error(t, err)
	require.Contains(t, err.Error(), "address 8.8.8.8: missing port in address")
}

func Test_WithDNSServer_NoPort_TransportNil(t *testing.T) {
	client, err := New(ClientConfig{})
	require.NoError(t, err)
	require.NotNil(t, client)
	// intentionally set to nil to see how WithDNSServer behaves
	client.httpClient.Transport = nil
	client = client.WithDNSServer("8.8.8.8")

	tr, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)

	_, err = tr.DialContext(context.Background(), "udp", "google.com:80")
	require.Error(t, err)
	require.Contains(t, err.Error(), "address 8.8.8.8: missing port in address")
}
