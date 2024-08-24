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

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt/dpop"
	grpccredentials "google.golang.org/grpc/credentials"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "credentials")

var (
	// TokenFieldNameGRPC specifies name for token
	TokenFieldNameGRPC = "authorization"

	// CacheTTL defines TTL for AWS cache
	CacheTTL = 5 * time.Minute
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

func (t Token) Expired() bool {
	if t.AccessToken == "" {
		return true
	}
	if t.Expires == nil {
		return false
	}

	now := time.Now().UTC()
	diff := t.Expires.Sub(now)
	expired := diff < time.Minute // 1 minute before actual expiration
	if expired {
		logger.KV(xlog.DEBUG,
			"now", now.Format("20060102T150405Z"),
			"expired", expired,
			"expires", t.Expires.Format("20060102T150405Z"),
			"expires_in", diff.String(),
		)
	}
	return expired
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

	if token.Expired() {
		if rc.callerIdentity != nil {
			ti, err := rc.callerIdentity.GetCallerIdentity(ctx)
			if err != nil {
				return nil, err
			}

			if ti.Expires == nil {
				exp := time.Now().Add(CacheTTL).UTC()
				ti.Expires = &exp
			}

			rc.authTokenMu.Lock()
			rc.token = *ti
			token = rc.token
			rc.authTokenMu.Unlock()

			logger.ContextKV(ctx, xlog.DEBUG,
				"status", "GetCallerIdentity",
				"expires", token.Expires.Format("20060102T150405Z"),
				"expires_in", time.Until(*token.Expires).String(),
			)
		}
		if token.AccessToken == "" {
			logger.ContextKV(ctx, xlog.DEBUG,
				"reason", "no_token",
			)
			return nil, nil
		}
	} /* else {
		logger.ContextKV(ctx, xlog.DEBUG,
			"status", "existing_token",
			"now", time.Now().UTC().Format("20060102T150405Z"),
			"expires", token.Expires.Format("20060102T150405Z"),
			"expires_in", time.Until(*token.Expires).String(),
		)
	} */

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
