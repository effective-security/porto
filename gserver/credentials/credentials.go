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
	"time"

	"github.com/effective-security/xpki/jwt/dpop"
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

// Token provides access token
type Token struct {
	TokenType   string
	AccessToken string
	// Expires is expiration time of the token
	Expires *time.Time
}

// CallerIdentity interface
type CallerIdentity interface {
	// GetCallerIdentity returns token
	GetCallerIdentity(ctx context.Context) (*Token, error)
}

// Bundle defines gRPC credential interface.
// see https://pkg.go.dev/google.golang.org/grpc/credentials
type Bundle interface {
	grpccredentials.Bundle
	UpdateAuthToken(token Token)
	WithDPoP(signer dpop.Signer)
	WithCallerIdentity(provider CallerIdentity)
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
	token          Token
	dpopSigner     dpop.Signer
	callerIdentity CallerIdentity
	authTokenMu    sync.RWMutex
}

func newPerRPCCredential() *perRPCCredential { return &perRPCCredential{} }

func (rc *perRPCCredential) RequireTransportSecurity() bool {
	return true
}

func (rc *perRPCCredential) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	rc.authTokenMu.RLock()
	token := rc.token
	rc.authTokenMu.RUnlock()

	if token.AccessToken == "" ||
		(token.Expires != nil && token.Expires.Before(time.Now())) {
		if rc.callerIdentity != nil {
			ti, err := rc.callerIdentity.GetCallerIdentity(ctx)
			if err != nil {
				return nil, err
			}
			rc.authTokenMu.Lock()
			rc.token = *ti
			token = rc.token
			rc.authTokenMu.Unlock()
		}
		if token.AccessToken == "" ||
			(token.Expires != nil && token.Expires.Before(time.Now())) {
			return nil, nil
		}
	}

	ri, _ := grpccredentials.RequestInfoFromContext(ctx)
	// if err := grpccredentials.CheckSecurityLevel(ri.AuthInfo, grpccredentials.PrivacyAndIntegrity); err != nil {
	// 	return nil, fmt.Errorf("unable to transfer Access Token: %v", err)
	// }

	res := map[string]string{
		TokenFieldNameGRPC: token.TokenType + " " + token.AccessToken,
	}

	if rc.dpopSigner != nil && strings.EqualFold(token.TokenType, "DPoP") {
		u := &url.URL{
			Path: ri.Method,
		}

		dhdr, err := rc.dpopSigner.Sign(ctx, "POST", u, nil)
		if err != nil {
			return nil, err
		}
		res["dpop"] = dhdr
	}

	return res, nil
}

func (b *bundle) UpdateAuthToken(token Token) {
	if b.rc != nil {
		b.rc.UpdateAuthToken(token)
	}
}

func (b *bundle) WithDPoP(signer dpop.Signer) {
	if b.rc != nil {
		b.rc.WithDPoP(signer)
	}
}

func (b *bundle) WithCallerIdentity(provider CallerIdentity) {
	if b.rc != nil {
		b.rc.WithPresignedToken(provider)
	}
}

func (rc *perRPCCredential) UpdateAuthToken(token Token) {
	rc.authTokenMu.Lock()
	rc.token = token
	rc.authTokenMu.Unlock()
}

func (rc *perRPCCredential) WithDPoP(signer dpop.Signer) {
	rc.authTokenMu.Lock()
	rc.dpopSigner = signer
	rc.authTokenMu.Unlock()
}

func (rc *perRPCCredential) WithPresignedToken(provider CallerIdentity) {
	rc.authTokenMu.Lock()
	rc.callerIdentity = provider
	rc.authTokenMu.Unlock()
}
