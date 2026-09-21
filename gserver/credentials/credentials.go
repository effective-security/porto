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

// TimeFormatISO8601 is the compact ISO 8601 layout ("yyyyMMddTHHmmssZ") used
// by AWS SigV4 presigned URLs and by TimeISO8601.
const TimeFormatISO8601 = "20060102T150405Z"

var (

	// TokenFieldNameGRPC is the gRPC metadata key carrying the access token.
	TokenFieldNameGRPC = "authorization"

	// CacheTTL is the default lifetime assigned to tokens from a
	// CallerIdentity that report no expiry, and the roles package AWS cache TTL.
	CacheTTL = 5 * time.Minute
)

// TimeISO8601 formats t using TimeFormatISO8601.
func TimeISO8601(t time.Time) string {
	return t.Format(TimeFormatISO8601)
}

// Config defines gRPC credential configuration.
type Config struct {
	// TLSConfig is the client or server TLS configuration wrapped by NewBundle.
	TLSConfig *tls.Config
}

// Token is an access token sent as "<TokenType> <AccessToken>" in the
// authorization metadata.
type Token struct {
	// TokenType is the scheme, e.g. "Bearer", "DPoP" or "AWS4".
	TokenType string
	// AccessToken is the raw token value.
	AccessToken string
	// Expires is expiration time of the token
	Expires *time.Time
}

// Expired reports whether the token is empty or expires within one minute.
// A token without Expires never expires.
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
			"now", TimeISO8601(now),
			"reason", "expired",
			"expired_at", expired,
			"token_expires", TimeISO8601(*t.Expires),
			"expires_in", diff.String(),
		)
	}
	return expired
}

// CallerIdentity obtains a fresh access token on demand; it is consulted by
// the per-RPC credentials whenever the current token has expired.
type CallerIdentity interface {
	// GetCallerIdentity returns a new token. If Expires is nil the token is
	// cached for CacheTTL.
	GetCallerIdentity(ctx context.Context) (*Token, error)
}

// Bundle is a grpccredentials.Bundle whose PerRPCCredentials sends the
// configured token. The setters are safe to call concurrently with RPCs.
// See https://pkg.go.dev/google.golang.org/grpc/credentials.
type Bundle interface {
	grpccredentials.Bundle
	// UpdateAuthToken replaces the token sent with subsequent RPCs.
	UpdateAuthToken(token Token)
	// WithDPoP sets the signer used to add a "dpop" proof to RPCs whose
	// token type is "DPoP".
	WithDPoP(signer dpop.Signer)
	// WithCallerIdentity sets the provider used to obtain a new token when
	// the current one has expired.
	WithCallerIdentity(provider CallerIdentity)
}

// NewBundle constructs a Bundle whose transport credentials wrap
// cfg.TLSConfig and whose per-RPC credentials require transport security.
// NewWithMode is not supported and returns nil, nil.
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

// OverrideServerName implements the (deprecated) grpccredentials.TransportCredentials
// method. gRPC no longer uses it; callers should use grpc.WithAuthority to override
// the authority on a channel instead of configuring the credentials. It is kept as a
// no-op to satisfy the interface.
func (tc *transportCredential) OverrideServerName(string) error {
	return nil
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

			// this is an infrequent operation, so log it
			logger.ContextKV(ctx, xlog.DEBUG,
				"status", "GetCallerIdentity",
				"expires", TimeISO8601(*token.Expires),
				"expires_in", time.Until(*token.Expires).String(),
			)
		}
		if token.AccessToken == "" {
			logger.ContextKV(ctx, xlog.DEBUG,
				"reason", "no_token",
			)
			return nil, nil
		}
	} /*else if token.Expires != nil {
		logger.ContextKV(ctx, xlog.DEBUG,
			"status", "existing_token",
			"now", TimeISO8601(time.Now().UTC()),
			"expires", TimeISO8601(*token.Expires),
			"expires_in", time.Until(*token.Expires).String(),
		)
	}*/

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
