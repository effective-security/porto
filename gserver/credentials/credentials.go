// Package credentials implements gRPC credential interface with etcd specific logic.
// e.g., client handshake with custom authority parameter
package credentials

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/effective-security/xpki/jwt/dpop"
	"google.golang.org/grpc/credentials"
	grpccredentials "google.golang.org/grpc/credentials"
)

var (
	// TokenFieldNameGRPC specifies name for token
	TokenFieldNameGRPC = "authorization"
)

// Config defines gRPC credential configuration.
type Config struct {
	TLSConfig *tls.Config
}

// Bundle defines gRPC credential interface.
// see https://pkg.go.dev/google.golang.org/grpc/credentials
type Bundle interface {
	grpccredentials.Bundle
	UpdateAuthToken(typ, token string)
	WithDPoP(signer dpop.Signer)
}

// NewBundle constructs a new gRPC credential bundle.
func NewBundle(cfg Config) Bundle {
	return &bundle{
		tc: newTransportCredential(cfg.TLSConfig),
		rc: newPerRPCCredential(),
	}
}

// bundle implements "grpccredentials.Bundle" interface.
type bundle struct {
	tc *transportCredential
	rc *perRPCCredential
}

func (b *bundle) TransportCredentials() grpccredentials.TransportCredentials {
	return b.tc
}

func (b *bundle) PerRPCCredentials() grpccredentials.PerRPCCredentials {
	return b.rc
}

func (b *bundle) NewWithMode(_ string) (grpccredentials.Bundle, error) {
	// no-op
	return nil, nil
}

// transportCredential implements "grpccredentials.TransportCredentials" interface.
type transportCredential struct {
	gtc grpccredentials.TransportCredentials
}

func newTransportCredential(cfg *tls.Config) *transportCredential {
	return &transportCredential{
		gtc: grpccredentials.NewTLS(cfg),
	}
}

func (tc *transportCredential) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, grpccredentials.AuthInfo, error) {
	return tc.gtc.ClientHandshake(ctx, authority, rawConn)
}

func (tc *transportCredential) ServerHandshake(rawConn net.Conn) (net.Conn, grpccredentials.AuthInfo, error) {
	return tc.gtc.ServerHandshake(rawConn)
}

func (tc *transportCredential) Info() grpccredentials.ProtocolInfo {
	return tc.gtc.Info()
}

func (tc *transportCredential) Clone() grpccredentials.TransportCredentials {
	return &transportCredential{
		gtc: tc.gtc.Clone(),
	}
}

func (tc *transportCredential) OverrideServerName(serverNameOverride string) error {
	return tc.gtc.OverrideServerName(serverNameOverride)
}

// perRPCCredential implements "grpccredentials.PerRPCCredentials" interface.
type perRPCCredential struct {
	tokenType   string
	accessToken string
	signer      dpop.Signer
	authTokenMu sync.RWMutex
}

func newPerRPCCredential() *perRPCCredential { return &perRPCCredential{} }

func (rc *perRPCCredential) RequireTransportSecurity() bool {
	return true
}

func (rc *perRPCCredential) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	rc.authTokenMu.RLock()
	typ := rc.tokenType
	authToken := rc.accessToken
	rc.authTokenMu.RUnlock()

	if authToken == "" {
		return nil, nil
	}

	ri, _ := credentials.RequestInfoFromContext(ctx)
	// if err := credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
	// 	return nil, fmt.Errorf("unable to transfer Access Token: %v", err)
	// }

	res := map[string]string{
		TokenFieldNameGRPC: typ + " " + authToken,
	}

	if rc.signer != nil && strings.EqualFold(typ, "DPoP") {
		u := &url.URL{
			Path: ri.Method,
		}

		dhdr, err := rc.signer.Sign(ctx, "POST", u, nil)
		if err != nil {
			return nil, err
		}
		res["dpop"] = dhdr
	}

	return res, nil
}

func (b *bundle) UpdateAuthToken(typ, token string) {
	if b.rc != nil {
		b.rc.UpdateAuthToken(typ, token)
	}
}

func (b *bundle) WithDPoP(signer dpop.Signer) {
	if b.rc != nil {
		b.rc.WithDPoP(signer)
	}
}

func (rc *perRPCCredential) UpdateAuthToken(typ, token string) {
	rc.authTokenMu.Lock()
	rc.tokenType = typ
	rc.accessToken = token
	rc.authTokenMu.Unlock()
}

func (rc *perRPCCredential) WithDPoP(signer dpop.Signer) {
	rc.authTokenMu.Lock()
	rc.signer = signer
	rc.authTokenMu.Unlock()
}
