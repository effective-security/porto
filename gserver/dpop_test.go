package gserver_test

import (
	"context"
	"crypto"
	"crypto/tls"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/gserver/roles"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/pkg/rpcclient"
	"github.com/effective-security/porto/tests/mockappcontainer"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type dpopTestCase struct {
	name       string
	serverName string
	authority  string
	unix       bool
	wantErr    bool
}

// TestGRPCDPoP authenticates unary and streaming calls using a real signed
// access token and the DPoP key loaded by rpcclient from storage.
func TestGRPCDPoP(t *testing.T) {
	t.Parallel()
	for _, tc := range []dpopTestCase{
		{name: "endpoint_authority"},
		{name: "tls_server_name", serverName: "api.example"},
		{name: "unix_socket", unix: true},
		{name: "hostless_authority", serverName: ":", wantErr: true},
		{name: "dial_authority", authority: "api.example:8443"},
		{name: "hostless_dial_authority", authority: ":", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testGRPCDPoP(t, tc)
		})
	}
}

func testGRPCDPoP(t *testing.T, tc dpopTestCase) {
	t.Helper()
	key, err := dpop.GenerateKey("")
	require.NoError(t, err)
	jkt, err := dpop.Thumbprint(key)
	require.NoError(t, err)
	issuerKey, err := dpop.GenerateKey("")
	require.NoError(t, err)
	issuer, err := jwt.NewProviderFromCryptoSigner(issuerKey.Key.(crypto.Signer))
	require.NoError(t, err)
	token, err := issuer.Sign(t.Context(), jwt.MapClaims{
		"sub":    "alice",
		"tenant": "example",
		"exp":    time.Now().Add(time.Hour),
		"cnf":    map[string]any{"jkt": jkt},
	})
	require.NoError(t, err)
	folder := t.TempDir()
	_, err = retriable.NewStorage(folder).SaveKey(key)
	require.NoError(t, err)

	svc := newEchoServer()
	cfg := &gserver.Config{
		ListenURLs: []string{"https://127.0.0.1:0"},
		Services:   []string{svc.Name()},
		ServerTLS: &gserver.TLSInfo{
			CertFile:      "testdata/test-server.pem",
			KeyFile:       "testdata/test-server-key.pem",
			TrustedCAFile: "testdata/test-server-rootca.pem",
		},
		IdentityMap: &roles.IdentityMap{
			Strict: true,
			DPoP: roles.JWTIdentityMap{
				Enabled:                  true,
				DefaultAuthenticatedRole: roles.DPoPUserRoleName,
			},
		},
	}
	container := mockappcontainer.NewBuilder().
		WithDiscovery(discovery.New()).
		WithJwtParser(issuer).
		Container()
	if tc.unix {
		cfg.ListenURLs = []string{"unixs://" + filepath.Join(folder, "rpc.sock")}
	}
	factories := map[string]gserver.ServiceFactory{
		svc.Name(): func(server gserver.GServer) any {
			return func() { server.AddService(svc) }
		},
	}
	observed := make(chan identity.Identity, 3)
	srv, err := gserver.Start("dpop", cfg, container, factories,
		gserver.WithUnaryServerInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			observed <- identity.FromContext(ctx).Identity()
			return handler(ctx, req)
		}),
		gserver.WithStreamServerInterceptor(func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			observed <- identity.FromContext(stream.Context()).Identity()
			return handler(srv, stream)
		}),
	)
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	addr := srv.(*gserver.Server).Listeners[0].Addr().String()
	endpoint := "https://" + addr
	if tc.unix {
		endpoint = cfg.ListenURLs[0]
	}
	var dialOptions []grpc.DialOption
	if tc.authority != "" {
		dialOptions = append(dialOptions, grpc.WithAuthority(tc.authority))
	}
	client, err := rpcclient.New(&rpcclient.Config{
		Endpoint: endpoint,
		// The legacy server fixture has no SANs.
		TLS: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         tc.serverName,
		},
		DialOptions:   dialOptions,
		StorageFolder: folder,
		AuthToken: &retriable.AuthToken{
			AccessToken: token,
			DpopJkt:     jkt,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	ctx, cancel := context.WithTimeout(t.Context(), echoTimeout)
	defer cancel()
	if tc.wantErr {
		_, err := callEcho(ctx, client.Conn(), []byte("authenticated"))
		require.ErrorContains(t, err, "an absolute HTTPS audience URI is required")
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		_, err = callWatch(ctx, client.Conn(), "authenticated")
		require.ErrorContains(t, err, "an absolute HTTPS audience URI is required")
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
		assert.Empty(t, observed)
		return
	}

	for range 2 {
		out, err := callEcho(ctx, client.Conn(), []byte("authenticated"))
		require.NoError(t, err)
		assert.Equal(t, "authenticated", string(out))
	}
	values, err := callWatch(ctx, client.Conn(), "authenticated")
	require.NoError(t, err)
	assert.Equal(t, []string{"authenticated", "authenticated", "authenticated"}, values)
	require.Len(t, observed, 3)
	for range 3 {
		id := <-observed
		require.NotNil(t, id)
		assert.Equal(t, identity.MethodDPoP, id.AuthMethod())
		assert.Equal(t, roles.DPoPUserRoleName, id.Role())
		assert.Equal(t, "alice", id.Subject())
		assert.Equal(t, "example", id.Tenant())
	}
}
