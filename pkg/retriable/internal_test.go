package retriable

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_WithDNSServer_UsingOptions_OK(t *testing.T) {
	client := New(WithTransport(http.DefaultTransport), WithDNSServer("8.8.8.8:53"))
	require.NotNil(t, client)

	tr, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	_, err := tr.DialContext(context.Background(), "tcp", "google.com:80")
	require.NoError(t, err)
}

func Test_WithDNSServer_UsingOptions_Fail(t *testing.T) {
	client := New(WithTransport(http.DefaultTransport), WithDNSServer("8.8.8.8"))
	require.NotNil(t, client)

	tr, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)

	_, err := tr.DialContext(context.Background(), "udp", "google.com:80")
	require.Error(t, err)
	require.Contains(t, err.Error(), "address 8.8.8.8: missing port in address")
}

func Test_WithDNSServer_OK(t *testing.T) {
	client1 := New().WithTransport(http.DefaultTransport).WithDNSServer("8.8.8.8:53")
	require.NotNil(t, client1)

	tr, ok := client1.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	_, err := tr.DialContext(context.Background(), "tcp", "google.com:80")
	require.NoError(t, err)

	client2 := New().WithDNSServer("8.8.8.8:53")
	require.NotNil(t, client2)

	tr, ok = client2.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	_, err = tr.DialContext(context.Background(), "tcp", "google.com:80")
	require.NoError(t, err)
}

func Test_WithDNSServer_NoPort(t *testing.T) {
	client := New().WithTransport(http.DefaultTransport.(*http.Transport).Clone()).WithDNSServer("8.8.8.8")
	require.NotNil(t, client)

	tr, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)

	_, err := tr.DialContext(context.Background(), "udp", "google.com:80")
	require.Error(t, err)
	require.Contains(t, err.Error(), "address 8.8.8.8: missing port in address")
}

func Test_WithDNSServer_NoPort_TransportNil(t *testing.T) {
	client := New()
	// intentionally set to nil to see how WithDNSServer behaves
	client.httpClient.Transport = nil
	client = client.WithDNSServer("8.8.8.8")

	tr, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)

	_, err := tr.DialContext(context.Background(), "udp", "google.com:80")
	require.Error(t, err)
	require.Contains(t, err.Error(), "address 8.8.8.8: missing port in address")
}
