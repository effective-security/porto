package rpcclient_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/rpcclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestNew(t *testing.T) {
	_, err := rpcclient.New(&rpcclient.Config{})
	assert.EqualError(t, err, "endpoint is required in client config")

	//serv := grpc.NewServer()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer lis.Close()

	client, err := rpcclient.NewFromURL(lis.Addr().String())
	require.NoError(t, err)

	assert.NotEmpty(t, client.Opts())
	assert.NotNil(t, client.Conn())

	defer client.Close()
}

func TestNewRejectsTLSOnInsecureEndpoint(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"localhost:443",
		"http://localhost:443",
		"unix:///tmp/service.sock",
	} {
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()
			client, err := rpcclient.New(&rpcclient.Config{
				Endpoint: endpoint,
				TLS:      &tls.Config{MinVersion: tls.VersionTLS12},
			})
			require.Nil(t, client)
			require.EqualError(t, err, "TLS requires an https:// or unixs:// endpoint")
		})
	}
}

func TestNewAcceptsTLSOnSecureEndpoint(t *testing.T) {
	t.Parallel()

	for _, network := range []string{
		"tcp",
		"unix",
	} {
		t.Run(network, func(t *testing.T) {
			t.Parallel()

			fixture := httptest.NewTLSServer(nil)
			serverCert := fixture.TLS.Certificates[0]
			rootCert := fixture.Certificate()
			fixture.Close()

			roots := x509.NewCertPool()
			roots.AddCert(rootCert)
			require.NotEmpty(t, rootCert.DNSNames)

			address := "127.0.0.1:0"
			if network == "unix" {
				address = filepath.Join(t.TempDir(), "service.sock")
			}
			listener, err := net.Listen(network, address)
			require.NoError(t, err)
			server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{serverCert},
				MinVersion:   tls.VersionTLS12,
			})))
			serveDone := make(chan error, 1)
			go func() {
				serveDone <- server.Serve(listener)
			}()
			t.Cleanup(func() {
				server.Stop()
				require.NoError(t, <-serveDone)
			})

			endpoint := "https://" + listener.Addr().String()
			if network == "unix" {
				endpoint = "unixs://" + listener.Addr().String()
			}
			client, err := rpcclient.New(&rpcclient.Config{
				Endpoint: endpoint,
				TLS: &tls.Config{
					RootCAs:    roots,
					ServerName: rootCert.DNSNames[0],
					MinVersion: tls.VersionTLS12,
				},
				DialTimeout: 3 * time.Second,
			})
			require.NoError(t, err)
			require.NotNil(t, client.Conn())
			require.NoError(t, client.Close())
		})
	}
}

func TestNewAcceptsUnixEndpointWithoutTLS(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "service.sock"))
	require.NoError(t, err)
	server := grpc.NewServer()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		require.NoError(t, <-serveDone)
	})

	client, err := rpcclient.New(&rpcclient.Config{
		Endpoint:    "unix://" + listener.Addr().String(),
		DialTimeout: 3 * time.Second,
	})
	require.NoError(t, err)
	require.NotNil(t, client.Conn())
	require.NoError(t, client.Close())
}
