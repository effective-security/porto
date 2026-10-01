package credentials_test

import (
	"context"
	"testing"

	"github.com/effective-security/porto/gserver/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	grpccredentials "google.golang.org/grpc/credentials"
)

func TestPerRPCDPoPURI(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		uri     []string
		method  string
		wantURI string
		wantErr string
	}{
		{
			name:    "default_port",
			uri:     []string{"https://api.example/porto.test.Echo"},
			method:  testRPCMethod,
			wantURI: "https://api.example" + testRPCMethod,
		},
		{
			name:    "ipv6_and_port",
			uri:     []string{"https://[::1]:8443/porto.test.Echo"},
			method:  testRPCMethod,
			wantURI: "https://[::1]:8443" + testRPCMethod,
		},
		{
			name:    "ipv6_zone",
			uri:     []string{"https://[fe80::1%25eth0]:8443/porto.test.Echo"},
			method:  testRPCMethod,
			wantURI: "https://[fe80::1%25eth0]:8443" + testRPCMethod,
		},
		{
			name:    "missing_audience",
			method:  testRPCMethod,
			wantErr: "a single gRPC audience URI is required",
		},
		{
			name:    "multiple_audiences",
			uri:     []string{testRPCAudience, testRPCAudience},
			method:  testRPCMethod,
			wantErr: "a single gRPC audience URI is required",
		},
		{
			name:    "relative_audience",
			uri:     []string{testRPCMethod},
			method:  testRPCMethod,
			wantErr: "an absolute HTTPS audience URI is required",
		},
		{
			name:    "missing_host",
			uri:     []string{"https:///porto.test.Echo"},
			method:  testRPCMethod,
			wantErr: "an absolute HTTPS audience URI is required",
		},
		{
			name:    "http_audience",
			uri:     []string{"http://api.example/porto.test.Echo"},
			method:  testRPCMethod,
			wantErr: "an absolute HTTPS audience URI is required",
		},
		{
			name:    "hostless_authority",
			uri:     []string{"https://:/porto.test.Echo"},
			method:  testRPCMethod,
			wantErr: "an absolute HTTPS audience URI is required",
		},
		{
			name:    "port_only_authority",
			uri:     []string{"https://:443/porto.test.Echo"},
			method:  testRPCMethod,
			wantErr: "an absolute HTTPS audience URI is required",
		},
		{
			name:    "userinfo",
			uri:     []string{"https://user@api.example/porto.test.Echo"},
			method:  testRPCMethod,
			wantErr: "an absolute HTTPS audience URI is required",
		},
		{
			name:    "malformed_audience",
			uri:     []string{"https://api.example:%/porto.test.Echo"},
			method:  testRPCMethod,
			wantErr: "unable to parse gRPC audience URI",
		},
		{
			name:    "missing_request_info",
			uri:     []string{testRPCAudience},
			wantErr: "a gRPC method is required",
		},
		{
			name:    "relative_method",
			uri:     []string{testRPCAudience},
			method:  "porto.test.Echo/Echo",
			wantErr: "a gRPC method is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := credentials.NewBundle(credentials.Config{})
			b.UpdateAuthToken(credentials.Token{TokenType: "DPoP", AccessToken: "token"})
			b.WithDPoP(testSigner{})
			ctx := context.Background()
			if tc.method != "" {
				ctx = grpccredentials.NewContextWithRequestInfo(ctx, grpccredentials.RequestInfo{Method: tc.method})
			}
			md, err := b.PerRPCCredentials().GetRequestMetadata(ctx, tc.uri...)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.Nil(t, md)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "POST "+tc.wantURI, md["dpop"])
		})
	}
}
