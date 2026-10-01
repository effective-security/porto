package rpcclient_test

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/rpcclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func TestNewRequiresConfig(t *testing.T) {
	t.Parallel()

	client, err := rpcclient.New(nil)
	require.Nil(t, client)
	require.EqualError(t, err, "endpoint is required in client config")
}

func TestNewTarget(t *testing.T) {
	t.Parallel()

	socket := filepath.Join(t.TempDir(), "service.sock")
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	tcs := []struct {
		endpoint string
		tls      *tls.Config
		target   string
	}{
		{endpoint: "http://api.example.test", target: "api.example.test:443"},
		{endpoint: "https://api.example.test", tls: tlsCfg, target: "api.example.test:443"},
		{endpoint: "https://api.example.test:8443", tls: tlsCfg, target: "api.example.test:8443"},
		{endpoint: "api.example.test:8080", target: "api.example.test:8080"},
		{endpoint: "api.example.test", target: "api.example.test:443"},
		{endpoint: "unix://" + socket, target: "unix://" + socket},
		{endpoint: "unixs://" + socket, tls: tlsCfg, target: "unix://" + socket},
	}
	for _, tc := range tcs {
		t.Run(tc.endpoint, func(t *testing.T) {
			t.Parallel()

			// without DialTimeout New does not connect or resolve
			client, err := rpcclient.New(&rpcclient.Config{
				Endpoint: tc.endpoint,
				TLS:      tc.tls,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			assert.Equal(t, tc.target, client.Conn().Target())
			assert.Equal(t, connectivity.Idle, client.Conn().GetState())
		})
	}
}

func TestNewDialCanceledContext(t *testing.T) {
	t.Parallel()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	// nothing listens on the socket, so the dial fails without the network
	target := "unix://" + filepath.Join(t.TempDir(), "service.sock")
	client, err := rpcclient.New(&rpcclient.Config{
		Endpoint:    target,
		Context:     canceled,
		DialTimeout: time.Minute,
	})
	require.Nil(t, client)
	// FINDINGS P-103: the context error is dropped
	require.ErrorContains(t, err, `failed to connect to "`+target+`"`)
}

func TestNewDialTimeoutExpires(t *testing.T) {
	t.Parallel()

	// nothing listens on a closed listener's port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	const timeout = 200 * time.Millisecond
	started := time.Now()
	client, err := rpcclient.New(&rpcclient.Config{
		Endpoint:    "http://" + addr,
		DialTimeout: timeout,
	})
	require.Nil(t, client)
	require.EqualError(t, err, `failed to connect to "`+addr+`" within 200ms`)
	assert.GreaterOrEqual(t, time.Since(started), timeout)
}

func TestNewLazyDialSucceedsWithoutServer(t *testing.T) {
	t.Parallel()

	// without DialTimeout New does not connect, so neither the canceled
	// Context nor the unreachable endpoint fails New, and the connection
	// stays Idle until the first RPC
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	client, err := rpcclient.New(&rpcclient.Config{
		Endpoint: "http://127.0.0.1:1",
		Context:  canceled,
	})
	require.NoError(t, err)
	assert.Equal(t, connectivity.Idle, client.Conn().GetState())
	require.NoError(t, client.Close())
}

func TestNewRejectsInvalidDialOptions(t *testing.T) {
	t.Parallel()

	client, err := rpcclient.New(&rpcclient.Config{
		Endpoint:    "http://127.0.0.1:1",
		DialOptions: []grpc.DialOption{grpc.WithDefaultServiceConfig("{")},
	})
	require.Nil(t, client)
	require.ErrorContains(t, err, "grpc: the provided default service config is invalid")
}

func TestClientCallOptions(t *testing.T) {
	t.Parallel()

	srv := startTestServer(t, false)

	tcs := []struct {
		name    string
		cfg     rpcclient.Config
		service string
		expOpts int
		expCode codes.Code
	}{
		{
			name:    "defaults",
			expOpts: 3,
			expCode: codes.OK,
		},
		{
			name: "receive limit",
			// the SERVING response is 2 bytes
			cfg:     rpcclient.Config{MaxRecvMsgSize: 1},
			expOpts: 3,
			expCode: codes.ResourceExhausted,
		},
		{
			name:    "send limit",
			cfg:     rpcclient.Config{MaxSendMsgSize: 1},
			service: "porto",
			expOpts: 3,
			expCode: codes.ResourceExhausted,
		},
		{
			name: "call options replace the limits",
			cfg: rpcclient.Config{
				MaxRecvMsgSize: 1,
				MaxSendMsgSize: 1,
				CallOptions:    []grpc.CallOption{grpc.WaitForReady(true)},
			},
			expOpts: 1,
			expCode: codes.OK,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := tc.cfg
			cfg.Endpoint = srv.endpoint
			cfg.DialTimeout = 3 * time.Second
			client, err := rpcclient.New(&cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			assert.Equal(t, connectivity.Ready, client.Conn().GetState())

			opts := client.Opts()
			require.Len(t, opts, tc.expOpts)
			if len(cfg.CallOptions) > 0 {
				assert.Equal(t, cfg.CallOptions, opts)
			}

			res, err := healthCheck(t.Context(), client.Conn(), tc.service, opts...)
			require.Equal(t, tc.expCode, status.Code(err), "%v", err)
			if tc.expCode == codes.OK {
				assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, res.GetStatus())
			}
		})
	}
}

func TestClientClose(t *testing.T) {
	t.Parallel()

	srv := startTestServer(t, false)
	client, err := rpcclient.New(&rpcclient.Config{
		Endpoint:    srv.endpoint,
		DialTimeout: 3 * time.Second,
	})
	require.NoError(t, err)

	_, err = healthCheck(t.Context(), client.Conn(), "", client.Opts()...)
	require.NoError(t, err)

	require.NoError(t, client.Close())
	assert.Equal(t, connectivity.Shutdown, client.Conn().GetState())

	_, err = healthCheck(t.Context(), client.Conn(), "", client.Opts()...)
	assert.Equal(t, codes.Canceled, status.Code(err))

	// the connection reports Canceled when closed again, which Close maps
	// to the error of the client context it canceled
	err = client.Close()
	require.ErrorIs(t, err, context.Canceled)
}
