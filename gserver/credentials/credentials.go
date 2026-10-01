package credentials

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt/dpop"
	grpccredentials "google.golang.org/grpc/credentials"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "credentials")

// TimeFormatISO8601 is the compact ISO 8601 layout ("yyyyMMddTHHmmssZ") used
// by AWS SigV4 presigned URLs and by TimeISO8601.
const TimeFormatISO8601 = "20060102T150405Z"

const (
	// dpopTokenType is the token type that gets a DPoP proof per RPC.
	dpopTokenType = "DPoP"
	// dpopFieldNameGRPC is the gRPC metadata key carrying the DPoP proof.
	dpopFieldNameGRPC = "dpop"
	// schemeHTTPS is the scheme of grpc-go's credential audience and of the
	// DPoP proof URI.
	schemeHTTPS = "https"
)

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
// Concurrent RPCs that find the token expired share one GetCallerIdentity
// call, made with the context of the RPC that started it.
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
	// the current one has expired. A token refresh already running is
	// discarded, and RPCs waiting for it ask the new provider.
	WithCallerIdentity(provider CallerIdentity)
}

// NewBundle constructs a Bundle whose transport credentials wrap
// cfg.TLSConfig and whose per-RPC credentials require transport security.
// NewWithMode is not supported and returns an error.
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

// NewWithMode implements grpccredentials.Bundle. Mode switching, which the
// grpclb and RLS balancers request, is not supported: it returns an error
// instead of a copy that would send this bundle's token to a balancer.
func (b *bundle) NewWithMode(mode string) (grpccredentials.Bundle, error) {
	return nil, errors.Errorf("credentials bundle mode %q is not supported", mode)
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
// mu guards every field; refresh is the in-flight CallerIdentity call that
// concurrent RPCs with an expired token wait for.
type perRPCCredential struct {
	mu             sync.RWMutex
	token          Token
	dpopSigner     dpop.Signer
	callerIdentity CallerIdentity
	refresh        *tokenRefresh
}

// tokenRefresh is one CallerIdentity call. done is closed after token, err
// and canceled are set, or after superseded is set when WithCallerIdentity
// replaced the provider.
type tokenRefresh struct {
	done  chan struct{}
	token Token
	err   error
	// canceled is set when the context of the RPC that made the call ended.
	canceled   bool
	superseded bool
}

func newPerRPCCredential() *perRPCCredential { return &perRPCCredential{} }

func (rc *perRPCCredential) RequireTransportSecurity() bool {
	return true
}

func (rc *perRPCCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	rc.mu.RLock()
	token := rc.token
	provider := rc.callerIdentity
	signer := rc.dpopSigner
	rc.mu.RUnlock()

	if token.Expired() {
		if provider != nil {
			var err error
			token, err = rc.refreshToken(ctx)
			if err != nil {
				return nil, err
			}
			// the provider may have installed the signer bound to the new
			// token with WithDPoP
			rc.mu.RLock()
			signer = rc.dpopSigner
			rc.mu.RUnlock()
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

	res := map[string]string{
		TokenFieldNameGRPC: token.TokenType + " " + token.AccessToken,
	}

	if signer != nil && strings.EqualFold(token.TokenType, dpopTokenType) {
		if len(uri) != 1 {
			return nil, errors.New("unable to sign DPoP proof: a single gRPC audience URI is required")
		}
		audience, err := url.Parse(uri[0])
		if err != nil {
			return nil, errors.WithMessage(err, "unable to parse gRPC audience URI")
		}
		if audience.Scheme != schemeHTTPS || audience.Hostname() == "" || audience.User != nil || audience.Opaque != "" {
			return nil, errors.New("unable to sign DPoP proof: an absolute HTTPS audience URI is required")
		}
		ri, ok := grpccredentials.RequestInfoFromContext(ctx)
		if !ok || !strings.HasPrefix(ri.Method, "/") {
			return nil, errors.New("unable to sign DPoP proof: a gRPC method is required")
		}
		// grpc-go's audience names the authority and service. Bind the proof
		// to that authority and the full method instead of only the service.
		u := &url.URL{
			Scheme: audience.Scheme,
			Host:   audience.Host,
			Path:   ri.Method,
		}

		dhdr, err := signer.Sign(ctx, http.MethodPost, u, nil)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to sign DPoP proof")
		}
		res[dpopFieldNameGRPC] = dhdr
	}

	return res, nil
}

// refreshToken returns the current token when it has not expired, and
// otherwise a token from the CallerIdentity provider. Concurrent callers
// share one provider call, made with the context of the RPC that started
// it: a waiter returns its token or error, or its own context error if that
// ends first. A live waiter makes the next call when the shared one failed
// after its RPC's context ended, or when WithCallerIdentity replaced the
// provider meanwhile.
func (rc *perRPCCredential) refreshToken(ctx context.Context) (Token, error) {
	for {
		rc.mu.Lock()
		provider := rc.callerIdentity
		token := rc.token
		if provider == nil || !token.Expired() {
			rc.mu.Unlock()
			return token, nil
		}
		if refresh := rc.refresh; refresh != nil {
			rc.mu.Unlock()
			select {
			case <-refresh.done:
				if err := ctx.Err(); err != nil {
					return Token{}, errors.WithStack(err)
				}
				if refresh.superseded || (refresh.err != nil && refresh.canceled) {
					continue
				}
				return refresh.token, refresh.err
			case <-ctx.Done():
				return Token{}, errors.WithStack(ctx.Err())
			}
		}
		// a superseded caller may come back here after its RPC ended
		if err := ctx.Err(); err != nil {
			rc.mu.Unlock()
			return Token{}, errors.WithStack(err)
		}
		refresh := &tokenRefresh{done: make(chan struct{})}
		rc.refresh = refresh
		rc.mu.Unlock()

		token, current, err := rc.leadRefresh(ctx, provider, refresh)
		if !current {
			continue
		}
		if err != nil {
			return Token{}, err
		}

		// this is an infrequent operation, so log it
		logger.ContextKV(ctx, xlog.DEBUG,
			"status", "GetCallerIdentity",
			"expires", TimeISO8601(*token.Expires),
			"expires_in", time.Until(*token.Expires).String(),
		)
		return token, nil
	}
}

// leadRefresh makes the provider call of refresh and publishes its result.
// current is false when WithCallerIdentity superseded refresh and the result
// was discarded. If the provider panics, the waiters are released with an
// error and the panic continues.
func (rc *perRPCCredential) leadRefresh(ctx context.Context, provider CallerIdentity, refresh *tokenRefresh) (token Token, current bool, err error) {
	panicked := true
	defer func() {
		if panicked {
			rc.finishRefresh(refresh, Token{}, errors.New("caller identity provider panicked"), false)
		}
	}()
	token, err = fetchToken(ctx, provider)
	panicked = false
	current = rc.finishRefresh(refresh, token, err, ctx.Err() != nil)
	return token, current, err
}

// finishRefresh stores the result of refresh and wakes its waiters. It
// reports false, and changes nothing, when refresh was superseded.
func (rc *perRPCCredential) finishRefresh(refresh *tokenRefresh, token Token, err error, canceled bool) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.refresh != refresh {
		return false
	}
	if err == nil {
		rc.token = token
	}
	refresh.token = token
	refresh.err = err
	refresh.canceled = canceled
	rc.refresh = nil
	close(refresh.done)
	return true
}

// fetchToken calls provider and returns a copy of its token that always has
// an expiry: CacheTTL from now when the provider sets none.
func fetchToken(ctx context.Context, provider CallerIdentity) (Token, error) {
	fresh, err := provider.GetCallerIdentity(ctx)
	if err != nil {
		return Token{}, errors.WithMessage(err, "unable to get caller identity")
	}
	if fresh == nil {
		return Token{}, errors.New("caller identity returned no token")
	}
	token := copyToken(*fresh)
	if token.Expires == nil {
		expires := time.Now().Add(CacheTTL).UTC()
		token.Expires = &expires
	}
	return token, nil
}

// copyToken returns t with its own copy of Expires, so a caller that keeps
// the pointer cannot change the stored token.
func copyToken(t Token) Token {
	if t.Expires != nil {
		expires := *t.Expires
		t.Expires = &expires
	}
	return t
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
	token = copyToken(token)
	rc.mu.Lock()
	rc.token = token
	rc.mu.Unlock()
}

func (rc *perRPCCredential) WithDPoP(signer dpop.Signer) {
	rc.mu.Lock()
	rc.dpopSigner = signer
	rc.mu.Unlock()
}

func (rc *perRPCCredential) WithPresignedToken(provider CallerIdentity) {
	rc.mu.Lock()
	rc.callerIdentity = provider
	if refresh := rc.refresh; refresh != nil {
		// the running call's result is discarded; its caller and the
		// waiters start again with provider
		refresh.superseded = true
		rc.refresh = nil
		close(refresh.done)
	}
	rc.mu.Unlock()
}
