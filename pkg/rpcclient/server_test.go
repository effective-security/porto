package rpcclient_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// healthCheckMethod is the full gRPC method name of the health Check RPC
// that the test server answers.
const healthCheckMethod = "/grpc.health.v1.Health/Check"

// testServer is an in-process gRPC server with the standard health service
// that records the metadata of the last unary call it received.
type testServer struct {
	// endpoint is the address to put in rpcclient.Config.Endpoint.
	endpoint string
	// clientTLS trusts the server certificate; nil for a plaintext server.
	clientTLS *tls.Config

	mu sync.Mutex
	md metadata.MD
}

// lastMD returns a copy of the metadata of the last received unary call.
func (s *testServer) lastMD() metadata.MD {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.md.Copy()
}

// startTestServer starts a gRPC server on 127.0.0.1 with the health service
// reporting SERVING; with secure it serves TLS and its endpoint uses the
// https:// scheme. The server is stopped when the test ends.
func startTestServer(t *testing.T, secure bool) *testServer {
	t.Helper()

	ts := &testServer{}
	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			ts.mu.Lock()
			ts.md = md.Copy()
			ts.mu.Unlock()
			return handler(ctx, req)
		}),
	}

	scheme := "http://"
	if secure {
		fixture := httptest.NewTLSServer(nil)
		serverCert := fixture.TLS.Certificates[0]
		rootCert := fixture.Certificate()
		fixture.Close()
		require.NotEmpty(t, rootCert.DNSNames)

		roots := x509.NewCertPool()
		roots.AddCert(rootCert)
		ts.clientTLS = &tls.Config{
			RootCAs:    roots,
			ServerName: rootCert.DNSNames[0],
			MinVersion: tls.VersionTLS12,
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
		})))
		scheme = "https://"
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ts.endpoint = scheme + listener.Addr().String()

	server := grpc.NewServer(opts...)
	grpc_health_v1.RegisterHealthServer(server, health.NewServer())

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		require.NoError(t, <-serveDone)
	})
	return ts
}

// healthCheck calls the health Check RPC on conn with opts.
func healthCheck(ctx context.Context, conn *grpc.ClientConn, service string, opts ...grpc.CallOption) (*grpc_health_v1.HealthCheckResponse, error) {
	return grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: service}, opts...)
}
