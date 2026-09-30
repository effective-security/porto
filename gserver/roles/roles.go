package roles

import (
	"cmp"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	tcredentials "github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	xslices "github.com/effective-security/x/slices"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/gigawattio/awsarn"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/gserver", "roles")

const (
	// GuestRoleName is the role of an unauthenticated caller
	GuestRoleName = "guest"

	// TLSUserRoleName is a suggested DefaultAuthenticatedRole for TLS identities
	TLSUserRoleName = "tls_user"

	// JWTUserRoleName is a suggested DefaultAuthenticatedRole for JWT identities
	JWTUserRoleName = "jwt_user"

	// DPoPUserRoleName is a suggested DefaultAuthenticatedRole for DPoP identities
	DPoPUserRoleName = "dpop_user"

	// AWSUserRoleName is a suggested DefaultAuthenticatedRole for AWS identities
	AWSUserRoleName = "aws_user"

	// DefaultSubjectClaim is the JWT claim used as identity subject when SubjectClaim is unset
	DefaultSubjectClaim = "sub"

	// DefaultRoleClaim is the JWT claim matched against Roles when RoleClaim is unset
	DefaultRoleClaim = "email"

	// DefaultTenantClaim is the JWT claim used as tenant when TenantClaim is unset
	DefaultTenantClaim = "tenant"

	awsTokenType    = "AWS4"
	bearerTokenType = "Bearer"
	dpopTokenType   = "DPoP"

	// awsCacheSize bounds the successful and the failed STS lookup caches.
	awsCacheSize = 100
	// awsFailureTTL is how long an STS rejection of a presigned URL is
	// remembered, so a repeated bad token does not repeat the outbound call.
	awsFailureTTL = 30 * time.Second

	// redactedValue replaces credential values in debug logs.
	redactedValue = "[REDACTED]"
)

// IdentityProvider extracts the caller identity from HTTP requests and gRPC
// contexts. IdentityFromRequest and IdentityFromContext are the mappers to
// pass to identity.NewContextHandler and identity.NewAuthUnaryInterceptor.
type IdentityProvider interface {
	// ApplicableForRequest returns true if the request carries credentials
	// (Authorization header, auth cookie or client certificate) for an enabled method.
	ApplicableForRequest(*http.Request) bool
	// IdentityFromRequest returns the identity of the HTTP caller, or the
	// guest identity when no enabled method matches. An error is returned
	// only for failed authentication in Strict mode.
	IdentityFromRequest(*http.Request) (identity.Identity, error)

	// ApplicableForContext returns true if the gRPC incoming metadata or peer
	// carries credentials for an enabled method.
	ApplicableForContext(ctx context.Context) bool
	// IdentityFromContext returns the identity of the gRPC caller for the
	// given method URI (used to verify DPoP proofs), or the guest identity.
	IdentityFromContext(ctx context.Context, uri string) (identity.Identity, error)
}

// provider is the IdentityProvider implementation returned by New.
type provider struct {
	config    IdentityMap
	dpopRoles map[string]string
	jwtRoles  map[string]string
	tlsRoles  map[string]string
	awsRoles  map[string]string
	jwt       jwt.Parser

	// sts is the client for STS lookups; tests replace it.
	sts *http.Client
	// awsCache holds successful lookups by presigned URL and awsFailures the
	// cacheable failures; awsLookups holds the running lookups, guarded by
	// lookupMu.
	awsCache    *expirable.LRU[string, *CallerIdentity]
	awsFailures *lru.Cache[string, awsFailure]
	lookupMu    sync.Mutex
	awsLookups  map[string]*awsLookup
}

// awsFailure is a cached STS rejection of a presigned URL, valid until expires.
type awsFailure struct {
	err     error
	expires time.Time
}

// awsLookup is one running STS lookup of a presigned URL; done is closed
// after ci, err and canceled are set.
type awsLookup struct {
	done chan struct{}
	ci   *CallerIdentity
	err  error
	// canceled is set when the context of the request that made the lookup ended.
	canceled bool
}

// New returns an IdentityProvider for the given map. jwt is required when
// JWT or DPoP is enabled and may be nil otherwise; cookies.csrf is required
// when JWT is enabled with cookies.auth. Missing claim names default to
// DefaultSubjectClaim, DefaultRoleClaim and DefaultTenantClaim.
// The provider is safe for concurrent use.
func New(config *IdentityMap, jwt jwt.Parser) (IdentityProvider, error) {
	if config.JWT.Enabled && config.Cookies.Auth != "" && config.Cookies.CSRF == "" {
		return nil, errors.New("cookies: csrf is required when auth is set")
	}
	awsFailures, err := lru.New[string, awsFailure](awsCacheSize)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create AWS failure cache")
	}
	// FINDINGS P-086: the cleanup goroutine of the expirable awsCache is never stopped.
	prov := &provider{
		config:      *config,
		dpopRoles:   make(map[string]string),
		jwtRoles:    make(map[string]string),
		tlsRoles:    make(map[string]string),
		awsRoles:    make(map[string]string),
		jwt:         jwt,
		sts:         stsHTTPClient,
		awsCache:    expirable.NewLRU[string, *CallerIdentity](awsCacheSize, nil, tcredentials.CacheTTL),
		awsFailures: awsFailures,
		awsLookups:  make(map[string]*awsLookup),
	}

	if config.AWS.Enabled {
		for role, users := range config.AWS.Roles {
			for _, user := range users {
				prov.awsRoles[user] = role
			}
		}
	}

	if config.DPoP.Enabled {
		if jwt == nil {
			return nil, errors.Errorf("dpop: JWT parser is required")
		}
		prov.config.DPoP.SubjectClaim = cmp.Or(prov.config.DPoP.SubjectClaim, DefaultSubjectClaim)
		prov.config.DPoP.RoleClaim = cmp.Or(prov.config.DPoP.RoleClaim, DefaultRoleClaim)
		prov.config.DPoP.TenantClaim = cmp.Or(prov.config.DPoP.TenantClaim, DefaultTenantClaim)

		for role, users := range config.DPoP.Roles {
			for _, user := range users {
				prov.dpopRoles[user] = role
			}
		}
	}
	if config.JWT.Enabled {
		if jwt == nil {
			return nil, errors.Errorf("jwt: JWT parser is required")
		}
		prov.config.JWT.SubjectClaim = cmp.Or(prov.config.JWT.SubjectClaim, DefaultSubjectClaim)
		prov.config.JWT.RoleClaim = cmp.Or(prov.config.JWT.RoleClaim, DefaultRoleClaim)
		prov.config.JWT.TenantClaim = cmp.Or(prov.config.JWT.TenantClaim, DefaultTenantClaim)

		for role, users := range config.JWT.Roles {
			for _, user := range users {
				prov.jwtRoles[user] = role
			}
		}
	}
	if config.TLS.Enabled {
		for role, users := range config.TLS.Roles {
			for _, user := range users {
				prov.tlsRoles[user] = role
			}
		}
	}

	return prov, nil
}

// ApplicableForRequest implements IdentityProvider.
func (p *provider) ApplicableForRequest(r *http.Request) bool {
	if (p.config.AWS.Enabled || p.config.DPoP.Enabled || p.config.JWT.Enabled) &&
		r.Header.Get(header.Authorization) != "" {
		return true
	}
	if p.config.JWT.Enabled && p.config.Cookies.Auth != "" {
		cookie, err := r.Cookie(p.config.Cookies.Auth)
		if err == nil && cookie.Value != "" {
			return true
		}
	}

	if p.config.TLS.Enabled && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return true
	}

	return false
}

// ApplicableForContext implements IdentityProvider.
func (p *provider) ApplicableForContext(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	authorization := ok && len(md.Get(tcredentials.TokenFieldNameGRPC)) > 0

	if authorization && (p.config.AWS.Enabled || p.config.DPoP.Enabled || p.config.JWT.Enabled) {
		return true
	}

	if p.config.JWT.Enabled && p.config.Cookies.Auth != "" {
		cookies := md.Get(header.Cookie)
		if len(cookies) > 0 {
			token, err := extractCookie(cookies, p.config.Cookies.Auth)
			if err == nil && token != "" {
				return true
			}
		}
	}

	if p.config.TLS.Enabled {
		c, ok := peer.FromContext(ctx)
		if ok {
			si, ok := c.AuthInfo.(credentials.TLSInfo)
			if ok && len(si.State.PeerCertificates) > 0 {
				return true
			}
		}
	}

	return false
}

func extractCookie(cookieHeaders []string, name string) (string, error) {
	h := http.Header{}
	for _, c := range cookieHeaders {
		h.Add("Cookie", c)
	}

	req := http.Request{Header: h}
	cookie, err := req.Cookie(name)
	if err != nil {
		return "", err
	}

	return cookie.Value, nil
}

func tokenType(auth string) (token string, tokenType string) {
	if auth == "" {
		return
	}

	idx := strings.Index(auth, " ")
	if idx == -1 {
		token = auth
		tokenType = bearerTokenType
		return
	}
	tokenType = auth[:idx]
	token = auth[idx+1:]
	return
}

// IdentityFromRequest implements IdentityProvider. Methods are tried in the
// order AWS4, DPoP, Bearer JWT (header or cookie), TLS client certificate;
// paths listed in SkipAuthPaths short-circuit to the guest identity.
func (p *provider) IdentityFromRequest(r *http.Request) (identity.Identity, error) {
	if slices.Contains(p.config.SkipAuthPaths, r.URL.Path) {
		logger.ContextKV(r.Context(), xlog.DEBUG, "reason", "skipped", "path", r.URL.Path)
		return identity.GuestIdentityMapper(r)
	}

	peers := getPeerCertAndCount(r)
	// logger.ContextKV(r.Context(), xlog.DEBUG,
	// 	"dpop_enabled", p.config.DPoP.Enabled,
	// 	"jwt_enabled", p.config.JWT.Enabled,
	// 	"tls_enabled", p.config.TLS.Enabled,
	// 	"certs_present", peers)

	isCookieAuth := false
	authHeader := r.Header.Get(header.Authorization)
	if authHeader == "" && p.config.JWT.Enabled && p.config.Cookies.Auth != "" {
		cookie, err := r.Cookie(p.config.Cookies.Auth)
		if err == nil && cookie.Value != "" && p.config.Cookies.CSRF != "" {
			// Enforce CSRF protections when falling back to cookie-based auth
			err := enforceCSRFCookieAndHeader(r, p.config.Cookies.CSRF)
			if err != nil {
				logger.ContextKV(r.Context(), xlog.DEBUG, "reason", "enforceCSRFCookieAndHeader", "err", err.Error())
			} else {
				authHeader = cookie.Value
				isCookieAuth = true
				logger.ContextKV(r.Context(), xlog.DEBUG, "cookie_set", "true", "path", r.URL.Path)
			}
		}
	}
	token, typ := tokenType(authHeader)

	var err error
	var id identity.Identity

	ctx := r.Context()
	if authHeader != "" && p.config.AWS.Enabled && strings.EqualFold(typ, awsTokenType) {
		id, err = p.awsIdentity(ctx, token, typ)
		if err == nil {
			return id, nil
		} else if p.config.Strict {
			return nil, err
		}
		logger.ContextKV(ctx, xlog.DEBUG, "reason", "awsIdentity", "err", err.Error())
	}

	if authHeader != "" && p.config.DPoP.Enabled && strings.EqualFold(typ, dpopTokenType) {
		phdr := r.Header.Get(dpop.HTTPHeader)
		u := r.URL
		coreURL := url.URL{
			Scheme: cmp.Or(u.Scheme, "https"),
			Host:   cmp.Or(u.Host, r.Host),
			Path:   u.Path,
		}

		id, err = p.dpopIdentity(ctx, phdr, r.Method, coreURL.String(), token, dpopTokenType)
		if err == nil {
			return id, nil
		} else if p.config.Strict {
			return nil, err
		}
		logger.ContextKV(ctx, xlog.DEBUG, "reason", "dpopIdentity", "err", err.Error())
	}

	if authHeader != "" && p.config.JWT.Enabled && strings.EqualFold(typ, bearerTokenType) {
		id, err = p.jwtIdentity(r.Context(), token, typ, values.Select(isCookieAuth, identity.MethodJWTCookie, identity.MethodJWT))
		if err == nil {
			return id, nil
		}

		if p.config.Strict && !isCookieAuth {
			return nil, err
		}
		// For Cookie-based auth, we don't return an error.
		logger.ContextKV(ctx, xlog.DEBUG, "reason", "jwtIdentity", "is_cookie", isCookieAuth, "err", err.Error())
	}

	if p.config.TLS.Enabled && peers > 0 {
		id, err = p.tlsIdentity(r.TLS)
		if err == nil {
			return id, nil
		} else if p.config.Strict {
			return nil, err
		}
		logger.ContextKV(ctx, xlog.DEBUG, "reason", "tlsIdentity", "err", err.Error())
	}

	// if none of mappers are applicable or configured,
	// then use default guest mapper
	return identity.GuestIdentityMapper(r)
}

func getPeerCertAndCount(r *http.Request) int {
	if r.TLS != nil {
		return len(r.TLS.PeerCertificates)
	}
	return 0
}

// sensitiveMetadata lists the metadata keys whose values dumpDM redacts.
var sensitiveMetadata = []string{
	strings.ToLower(tcredentials.TokenFieldNameGRPC),
	strings.ToLower(header.ProxyAuthorization),
	strings.ToLower(header.Cookie),
	strings.ToLower(header.DPoP),
	strings.ToLower(header.XCSRFToken),
}

// dumpDM returns the first value of each metadata key as key-value pairs
// for debug logs, with credential values redacted.
func dumpDM(md metadata.MD) []any {
	var res []any
	for k, v := range md {
		if len(v) > 0 {
			val := v[0]
			if slices.Contains(sensitiveMetadata, strings.ToLower(k)) {
				val = redactedValue
			}
			res = append(res, k, val)
		}
	}
	return res
}

// IdentityFromContext implements IdentityProvider. It reads the
// "authorization", "dpop", "cookie" and "x-csrf-token" incoming metadata
// keys and the peer TLS state; SkipAuthPaths is not consulted. Cookie auth
// requires the CSRF double-submit check on every call.
func (p *provider) IdentityFromContext(ctx context.Context, uri string) (identity.Identity, error) {
	// a context without metadata has a nil MD, whose Get returns nil
	md, _ := metadata.FromIncomingContext(ctx)
	authorization := md.Get(tcredentials.TokenFieldNameGRPC)
	cookies := md.Get(header.Cookie)
	if len(authorization) > 0 {
		token, typ := tokenType(authorization[0])

		if p.config.DebugLogs {
			logger.ContextKV(ctx, xlog.DEBUG,
				"uri", uri,
				"token_type", typ,
			)
			logger.ContextKV(ctx, xlog.DEBUG, dumpDM(md)...)
		}

		if token != "" && p.config.AWS.Enabled &&
			strings.EqualFold(typ, awsTokenType) {
			id, err := p.awsIdentity(ctx, token, typ)
			if err == nil {
				return id, nil
			} else if p.config.Strict {
				return nil, err
			}
			logger.ContextKV(ctx, xlog.DEBUG, "reason", "awsIdentity", "err", err.Error())
		}

		dhdr := md.Get(header.DPoP)
		if token != "" && p.config.DPoP.Enabled &&
			strings.EqualFold(typ, dpopTokenType) && len(dhdr) > 0 {
			id, err := p.dpopIdentity(ctx, dhdr[0], http.MethodPost, uri, token, dpopTokenType)
			if err == nil {
				return id, nil
			} else if p.config.Strict {
				return nil, err
			}
			logger.ContextKV(ctx, xlog.DEBUG, "reason", "dpopIdentity", "err", err.Error())
		}

		if token != "" && p.config.JWT.Enabled && strings.EqualFold(typ, bearerTokenType) {
			id, err := p.jwtIdentity(ctx, token, typ, identity.MethodJWT)
			if err == nil {
				return id, nil
			} else if p.config.Strict {
				return nil, err
			}
			logger.ContextKV(ctx, xlog.DEBUG, "reason", "jwtIdentity", "err", err.Error())
		}
		logger.ContextKV(ctx, xlog.DEBUG, "reason", "no_token_found")
	} else if p.config.JWT.Enabled && p.config.Cookies.Auth != "" && len(cookies) > 0 {
		cookie, err := extractCookie(cookies, p.config.Cookies.Auth)
		if err == nil && cookie != "" {
			// Every RPC is a POST, so cookie auth always needs the CSRF check.
			if err := enforceCSRFMetadata(md, cookies, p.config.Cookies.CSRF); err != nil {
				logger.ContextKV(ctx, xlog.DEBUG, "reason", "enforceCSRFMetadata", "err", err.Error())
			} else if token, typ := tokenType(cookie); token != "" {
				id, err := p.jwtIdentity(ctx, token, typ, identity.MethodJWTCookie)
				if err == nil {
					return id, nil
				}

				// For Cookie-based auth, we don't return an error.
				logger.ContextKV(ctx, xlog.DEBUG,
					"reason", "cookie_based_auth",
					"type", typ,
					"token", xslices.StringUpto(token, 12),
					"err", err.Error())
			}
		}
	} else {
		logger.ContextKV(ctx, xlog.DEBUG, "reason", "no_metadata_incoming")
	}

	if p.config.TLS.Enabled {
		c, ok := peer.FromContext(ctx)
		if ok {
			si, ok := c.AuthInfo.(credentials.TLSInfo)
			if ok && len(si.State.PeerCertificates) > 0 {
				id, err := p.tlsIdentity(&si.State)
				if err == nil {
					return id, nil
				} else if p.config.Strict {
					return nil, err
				}
				logger.ContextKV(ctx, xlog.DEBUG, "reason", "tlsIdentity", "err", err.Error())
			}
		}
	}
	if p.config.DebugLogs {
		logger.ContextKV(ctx, xlog.DEBUG, "role", "guest")
	}
	return identity.GuestIdentityForContext(ctx, uri)
}

// enforceCSRFCookieAndHeader validates CSRF for unsafe HTTP methods when requests
// are authenticated via cookies (i.e., no Authorization header). It implements
// the "double submit cookie" pattern.
func enforceCSRFCookieAndHeader(r *http.Request, csrfCookieName string) error {
	if csrfCookieName == "" {
		return nil
	}
	// Safe/Idempotent methods do not require CSRF checks
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return nil
	}

	// If Authorization header is present, we consider it non-cookie auth and skip CSRF here
	if r.Header.Get(header.Authorization) != "" {
		return nil
	}

	// 1) Double-submit cookie check: X-CSRF-Token header must match csrf_token cookie
	cookieToken := ""
	if c, err := r.Cookie(csrfCookieName); err == nil {
		cookieToken = c.Value
	}
	if err := checkCSRF(r.Header.Get(header.XCSRFToken), cookieToken); err != nil {
		return err
	}

	/*
		// 2) Basic Origin/Referer host validation (best-effort)
		// Allow if either Origin or Referer (when present) matches request Host
		hostOK := true
		if origin := r.Header.Get("Origin"); origin != "" {
			if u, err := url.Parse(origin); err == nil {
				hostOK = strings.EqualFold(u.Host, r.Host)
			} else {
				hostOK = false
			}
		}
		if hostOK && r.Header.Get("Origin") == "" {
			if ref := r.Header.Get("Referer"); ref != "" {
				if u, err := url.Parse(ref); err == nil {
					hostOK = strings.EqualFold(u.Host, r.Host)
				} else {
					hostOK = false
				}
			}
		}
		if !hostOK {
			return errors.New("cross-site request not allowed")
		}
	*/
	return nil
}

// enforceCSRFMetadata applies the double-submit check to a gRPC call
// authenticated with the auth cookie: the x-csrf-token metadata must match
// the csrfCookieName cookie in cookies.
func enforceCSRFMetadata(md metadata.MD, cookies []string, csrfCookieName string) error {
	headerToken := ""
	if vals := md.Get(header.XCSRFToken); len(vals) > 0 {
		headerToken = vals[0]
	}
	// a missing cookie leaves cookieToken empty, which checkCSRF rejects
	cookieToken, _ := extractCookie(cookies, csrfCookieName)
	return checkCSRF(headerToken, cookieToken)
}

// checkCSRF compares the X-CSRF-Token value with the CSRF cookie value in
// constant time, ignoring surrounding spaces. The error never contains
// either value.
func checkCSRF(headerToken, cookieToken string) error {
	headerToken = strings.TrimSpace(headerToken)
	if headerToken == "" {
		return errors.New("missing X-CSRF-Token")
	}
	cookieToken = strings.TrimSpace(cookieToken)
	if cookieToken == "" {
		return errors.New("missing CSRF cookie")
	}
	if subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookieToken)) != 1 {
		return errors.New("CSRF token mismatch")
	}
	return nil
}

func (p *provider) dpopIdentity(ctx context.Context, phdr, method, uri string, auth, tokenType string) (identity.Identity, error) {
	res, err := dpop.VerifyClaims(dpop.VerifyConfig{}, phdr, method, uri)
	if err != nil {
		return nil, err
	}

	var claims jwt.MapClaims
	cfg := jwt.VerifyConfig{
		ExpectedIssuer: p.config.DPoP.Issuer,
	}
	if p.config.DPoP.Audience != "" {
		cfg.ExpectedAudience = []string{p.config.DPoP.Audience}
	}
	claims, err = p.jwt.ParseToken(ctx, auth, &cfg)
	if err != nil {
		return nil, err
	}

	tb, err := dpop.GetCnfClaim(claims)
	if err != nil {
		return nil, err
	}
	if tb != res.Thumbprint {
		logger.ContextKV(ctx, xlog.DEBUG, "header", tb, "claims", res.Thumbprint)
		return nil, errors.Errorf("dpop: thumbprint mismatch")
	}

	email := claims.String("email")
	subj := claims.String(p.config.DPoP.SubjectClaim)
	tenant := claims.String(p.config.DPoP.TenantClaim)
	roleClaim := claims.String(p.config.DPoP.RoleClaim)
	role := p.dpopRoles[roleClaim]
	if role == "" {
		role = p.config.DPoP.DefaultAuthenticatedRole
	}
	logger.ContextKV(ctx, xlog.DEBUG,
		"role", role,
		"tenant", tenant,
		"subject", subj,
		"email", email,
		"type", tokenType)
	return identity.NewIdentity(role, subj, tenant, claims, auth, tokenType, identity.MethodDPoP), nil
}

func (p *provider) awsIdentity(ctx context.Context, auth, tokenType string) (identity.Identity, error) {
	now := time.Now().UTC()
	u, err := base64.RawURLEncoding.DecodeString(auth)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid AWS4 token")
	}
	ci, err := p.awsCallerIdentity(ctx, string(u))
	if err != nil {
		return nil, err
	}

	if ci.Expires.Before(time.Now().UTC()) {
		return nil, errors.Errorf("AWS4 token has expired on %s, now %s", ci.Expires.Format("20060102T150405Z"), now.Format("20060102T150405Z"))
	}

	callerIdentity := ci.GetCallerIdentityResponse.GetCallerIdentityResult
	acc := callerIdentity.Account
	if len(p.config.AWS.AllowedAccounts) > 0 && !slices.Contains(p.config.AWS.AllowedAccounts, acc) {
		return nil, errors.Errorf("AWS account %q is not allowed", acc)
	}

	components, err := awsarn.Parse(callerIdentity.Arn)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to parse AWS ARN")
	}
	claims := map[string]any{
		"aws_arn": callerIdentity.Arn,
		//"aws_partition": components.Partition,
		//"aws_service":   components.Service,
		//"aws_region":     components.Region,
		"aws_account": components.AccountID,
		//"resource":   components.Resource,
		"aws_type": components.ResourceType,
	}
	res := components.Resource
	if components.ResourceType == "assumed-role" {
		art := strings.Split(components.Resource, components.ResourceDelimiter)
		res = art[0]
	}
	subj := fmt.Sprintf("%s:%s/%s", components.AccountID, components.ResourceType, res)

	role := cmp.Or(p.awsRoles[subj], p.awsRoles[callerIdentity.Arn], p.config.AWS.DefaultAuthenticatedRole)
	logger.KV(xlog.DEBUG,
		"account", callerIdentity.Account,
		"arn", callerIdentity.Arn,
		"user", callerIdentity.UserID,
		"role", role,
	)
	return identity.NewIdentity(role, subj, callerIdentity.Account, claims, auth, tokenType, identity.MethodAWS), nil
}

// awsCallerIdentity returns the STS caller identity for a presigned URL
// from the caches, or from one STS lookup that concurrent requests with the
// same URL share. The lookup runs with the context of the request that
// started it; a waiter returns its own context error if that ends first,
// and makes the next lookup when the shared one failed after its request's
// context ended.
func (p *provider) awsCallerIdentity(ctx context.Context, presignedURL string) (*CallerIdentity, error) {
	if ci, found, err := p.cachedAWS(presignedURL); found {
		return ci, err
	}

	expires, amzDate, amzExpiry, err := ParseSTSTokenExpiration(presignedURL)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to parse AWS4 token")
	}
	if err := ValidateSTSPresignedURL(presignedURL); err != nil {
		return nil, errors.WithMessage(err, "invalid AWS4 token")
	}

	for {
		p.lookupMu.Lock()
		// a lookup that ended after the check above has filled the caches:
		// results are cached before the lookup is removed
		if ci, found, err := p.cachedAWS(presignedURL); found {
			p.lookupMu.Unlock()
			return ci, err
		}
		if l := p.awsLookups[presignedURL]; l != nil {
			p.lookupMu.Unlock()
			select {
			case <-l.done:
				if err := ctx.Err(); err != nil {
					return nil, errors.WithMessage(err, "unable to get Caller Identity from AWS")
				}
				if l.err != nil && l.canceled {
					continue
				}
				return l.ci, l.err
			case <-ctx.Done():
				return nil, errors.WithMessage(ctx.Err(), "unable to get Caller Identity from AWS")
			}
		}
		l := &awsLookup{done: make(chan struct{})}
		p.awsLookups[presignedURL] = l
		p.lookupMu.Unlock()
		return p.leadAWSLookup(ctx, l, presignedURL, expires, amzDate, amzExpiry)
	}
}

// leadAWSLookup makes the STS lookup of l and publishes its result to the
// waiters. If the lookup panics, the waiters are released with an error and
// the panic continues on the request that made it.
func (p *provider) leadAWSLookup(ctx context.Context, l *awsLookup, presignedURL string, expires *time.Time, amzDate, amzExpiry string) (ci *CallerIdentity, err error) {
	panicked := true
	defer func() {
		if panicked {
			err = errors.New("STS lookup panicked")
		}
		p.lookupMu.Lock()
		delete(p.awsLookups, presignedURL)
		l.ci = ci
		l.err = err
		l.canceled = ctx.Err() != nil
		close(l.done)
		p.lookupMu.Unlock()
	}()
	ci, err = p.lookupAWS(ctx, presignedURL, expires, amzDate, amzExpiry)
	panicked = false
	return ci, err
}

// cachedAWS returns the cached lookup result for presignedURL; found is
// false when neither cache holds a current entry.
func (p *provider) cachedAWS(presignedURL string) (ci *CallerIdentity, found bool, err error) {
	if ci, ok := p.awsCache.Get(presignedURL); ok {
		return ci, true, nil
	}
	// an expired failure stays until a new lookup replaces it or it is evicted
	if f, ok := p.awsFailures.Get(presignedURL); ok && time.Now().Before(f.expires) {
		return nil, true, errors.WithMessage(f.err, "cached STS lookup failure")
	}
	return nil, false, nil
}

// lookupAWS calls STS with the presigned URL and caches the result. Only
// failures caused by the URL itself are cached (see cacheableSTSFailure and
// an undecodable response); transport errors, timeouts and transient
// responses are not.
func (p *provider) lookupAWS(ctx context.Context, presignedURL string, expires *time.Time, amzDate, amzExpiry string) (*CallerIdentity, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, presignedURL, nil)
	if err != nil {
		return nil, errors.WithMessage(withoutURL(err), "invalid AWS4 token")
	}
	r.Header.Set(header.Accept, header.ApplicationJSON)
	resp, err := p.sts.Do(r)
	if err != nil {
		return nil, errors.Wrapf(withoutURL(err), "unable to get Caller Identity from AWS host %s", r.URL.Host)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSTSResponseBytes))
	if err != nil {
		return nil, errors.WithMessage(err, "failed to decode AWS response")
	}

	if resp.StatusCode != http.StatusOK {
		// the presigned URL is a bearer credential; log only its host
		logger.ContextKV(ctx, xlog.WARNING,
			"host", r.URL.Host,
			"status", resp.StatusCode,
			"amz_date", amzDate,
			"amz_expiry", amzExpiry,
			"expires", tcredentials.TimeISO8601(*expires),
			"now", tcredentials.TimeISO8601(time.Now().UTC()),
			"body", string(body))
		err := errors.Errorf("failed to get Caller Identity from AWS: %s", resp.Status)
		if cacheableSTSFailure(resp.StatusCode, body) {
			p.addAWSFailure(presignedURL, err)
		}
		return nil, err
	}

	ci := new(CallerIdentity)
	if err := json.Unmarshal(body, ci); err != nil {
		logger.KV(xlog.ERROR,
			"body", string(body),
			"err", err.Error(),
		)
		err = errors.WithMessage(err, "failed to decode AWS response")
		p.addAWSFailure(presignedURL, err)
		return nil, err
	}
	ci.Expires = *expires
	p.awsCache.Add(presignedURL, ci)
	return ci, nil
}

// withoutURL returns the cause of a *url.Error, whose text holds the URL:
// a presigned URL is a bearer credential and must not reach errors or logs.
func withoutURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

// addAWSFailure caches err for presignedURL for awsFailureTTL.
func (p *provider) addAWSFailure(presignedURL string, err error) {
	p.awsFailures.Add(presignedURL, awsFailure{
		err:     err,
		expires: time.Now().Add(awsFailureTTL),
	})
}

// transientSTSErrorCodes are STS error codes that do not depend on the
// presigned URL. STS reports throttling with HTTP 400.
var transientSTSErrorCodes = []string{
	"Throttling",
	"ThrottlingException",
	"RequestLimitExceeded",
}

// cacheableSTSFailure reports whether an STS error response rejects the
// presigned URL itself: a 4xx status other than 408 and 429 whose error
// code is not in transientSTSErrorCodes.
func cacheableSTSFailure(status int, body []byte) bool {
	if status < http.StatusBadRequest || status >= http.StatusInternalServerError ||
		status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
		return false
	}
	return !slices.Contains(transientSTSErrorCodes, stsErrorCode(body))
}

// stsErrorCode returns the error code of an STS error response, in the JSON
// form that Accept: application/json selects or in the XML form, or "" when
// the body has neither.
func stsErrorCode(body []byte) string {
	var res struct {
		Error struct {
			Code string `json:"Code" xml:"Code"`
		} `json:"Error" xml:"Error"`
	}
	if json.Unmarshal(body, &res) == nil && res.Error.Code != "" {
		return res.Error.Code
	}
	if xml.Unmarshal(body, &res) == nil {
		return res.Error.Code
	}
	return ""
}

const (
	// stsRequestTimeout bounds the outbound GetCallerIdentity call so a slow
	// STS endpoint cannot stall request authentication indefinitely.
	stsRequestTimeout = 10 * time.Second
	// maxSTSResponseBytes bounds the body read from STS; a real
	// GetCallerIdentity response is well under 1 KiB.
	maxSTSResponseBytes = 64 << 10
	// stsGetCallerIdentityAction is the only STS action a presigned URL may carry.
	stsGetCallerIdentityAction = "GetCallerIdentity"
)

// awsRegionRe matches AWS region names such as us-east-1, cn-north-1,
// us-gov-west-1 and eu-isob-east-1.
var awsRegionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

// stsHTTPClient is the dedicated client for STS presigned-URL lookups.
// It has a timeout, unlike http.DefaultClient.
var stsHTTPClient = &http.Client{Timeout: stsRequestTimeout}

// ValidateSTSPresignedURL checks that a presigned URL supplied in an AWS4
// token is an HTTPS GetCallerIdentity request addressed to an AWS STS
// endpoint (sts.amazonaws.com, sts[-fips].<region>.amazonaws.com[.cn], or
// an STS VPC endpoint under amazonaws.com). Without this check the server
// would fetch an attacker-chosen URL and trust the returned account and ARN.
func ValidateSTSPresignedURL(presignedURL string) error {
	u, err := url.Parse(presignedURL)
	if err != nil {
		return errors.WithMessage(withoutURL(err), "failed to parse presigned URL")
	}
	if u.Scheme != "https" {
		return errors.Errorf("presigned URL must use https, got %q", u.Scheme)
	}
	if u.User != nil {
		return errors.New("presigned URL must not contain user info")
	}
	if !isSTSHost(u.Hostname()) {
		return errors.Errorf("presigned URL host %q is not an AWS STS endpoint", u.Hostname())
	}
	if action := u.Query().Get("Action"); action != stsGetCallerIdentityAction {
		return errors.Errorf("presigned URL action %q is not %s", action, stsGetCallerIdentityAction)
	}
	return nil
}

// isSTSHost reports whether host is an AWS STS endpoint. Accepted forms:
// sts.amazonaws.com, sts.<region>.amazonaws.com, sts-fips.<region>.amazonaws.com,
// sts.<region>.amazonaws.com.cn, and VPC endpoints of the form
// <vpce-id>.sts.<region>.vpce.amazonaws.com. Matching is on whole labels so
// other AWS-hosted names such as S3 buckets ("sts.s3.amazonaws.com") are rejected.
func isSTSHost(host string) bool {
	labels := strings.Split(strings.ToLower(host), ".")
	// strip the amazonaws.com / amazonaws.com.cn suffix
	n := len(labels)
	switch {
	case n >= 4 && labels[n-3] == "amazonaws" && labels[n-2] == "com" && labels[n-1] == "cn":
		labels = labels[:n-3]
	case n >= 3 && labels[n-2] == "amazonaws" && labels[n-1] == "com":
		labels = labels[:n-2]
	default:
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
	}
	switch len(labels) {
	case 1: // sts
		return labels[0] == "sts"
	case 2: // sts.<region> or sts-fips.<region>
		return (labels[0] == "sts" || labels[0] == "sts-fips") && awsRegionRe.MatchString(labels[1])
	case 4: // <vpce-id>.sts.<region>.vpce
		return strings.HasPrefix(labels[0], "vpce-") && labels[1] == "sts" &&
			awsRegionRe.MatchString(labels[2]) && labels[3] == "vpce"
	default:
		return false
	}
}

// ParseSTSTokenExpiration computes the expiry of an AWS SigV4 presigned URL
// from its X-Amz-Date and X-Amz-Expires query parameters. It also returns the
// raw parameter values for logging. An unparsable X-Amz-Expires falls back to
// credentials.CacheTTL.
func ParseSTSTokenExpiration(presignedURL string) (*time.Time, string, string, error) {
	u, err := url.Parse(presignedURL)
	if err != nil {
		return nil, "", "", errors.WithMessage(withoutURL(err), "failed to parse presigned URL")
	}
	q := u.Query()
	// The date and time format must follow the ISO 8601 standard, and must be formatted with the "yyyyMMddTHHmmssZ" format
	qexp := q.Get("X-Amz-Expires")
	qdate := q.Get("X-Amz-Date")
	if qexp == "" || qdate == "" {
		return nil, qdate, qexp, errors.Errorf("invalid presigned URL: missing X-Amz-Date or X-Amz-Expires")
	}
	qt, err := time.Parse("20060102T150405Z", qdate)
	if err != nil {
		return nil, qdate, qexp, errors.WithMessagef(err, "failed to parse X-Amz-Date: %s", qdate)
	}
	d, err := time.ParseDuration(qexp + "s")
	if err != nil {
		logger.KV(xlog.ERROR,
			"reason", "ParseDuration",
			"expiry_header", qexp,
			"err", err.Error())
		d = tcredentials.CacheTTL

	}
	exp := qt.Add(d).UTC()
	return &exp, qdate, qexp, nil
}

// CallerIdentity is the JSON response of the AWS STS GetCallerIdentity API,
// see https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html.
// It is cached per presigned URL until Expires.
type CallerIdentity struct {
	// GetCallerIdentityResponse is the response envelope.
	GetCallerIdentityResponse struct {
		GetCallerIdentityResult struct {
			Account string `json:"Account"`
			Arn     string `json:"Arn"`
			UserID  string `json:"UserId"`
		} `json:"GetCallerIdentityResult"`
		ResponseMetadata struct {
			RequestID string `json:"RequestId"`
		} `json:"ResponseMetadata"`
	} `json:"GetCallerIdentityResponse"`

	// Expires is the presigned URL expiry derived by ParseSTSTokenExpiration.
	Expires time.Time `json:"-"`
}

func (p *provider) jwtIdentity(ctx context.Context, auth, tokenType string, method identity.AuthMethod) (identity.Identity, error) {
	var claims jwt.MapClaims
	var err error

	cfg := jwt.VerifyConfig{
		ExpectedIssuer: p.config.JWT.Issuer,
	}
	if p.config.JWT.Audience != "" {
		cfg.ExpectedAudience = []string{p.config.JWT.Audience}
	}

	claims, err = p.jwt.ParseToken(ctx, auth, &cfg)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to parse %s %s token", method.String(), tokenType)
	}

	if claims.String("cnf") != "" {
		return nil, errors.Errorf("DPoP token used for %s %s authentication", method.String(), tokenType)
	}

	email := claims.String("email")
	subj := claims.String(p.config.JWT.SubjectClaim)
	tenant := claims.String(p.config.JWT.TenantClaim)
	roleClaim := claims.String(p.config.JWT.RoleClaim)
	role := cmp.Or(p.jwtRoles[roleClaim], p.config.JWT.DefaultAuthenticatedRole)
	logger.KV(xlog.DEBUG,
		"role", role,
		"tenant", tenant,
		"subject", subj,
		"email", email,
		"type", tokenType,
		"method", method.String(),
	)
	return identity.NewIdentity(role, subj, tenant, claims, auth, tokenType, method), nil
}

func (p *provider) tlsIdentity(TLS *tls.ConnectionState) (identity.Identity, error) {
	peer := TLS.PeerCertificates[0]
	if len(peer.URIs) == 1 && peer.URIs[0].Scheme == "spiffe" {
		spiffe := peer.URIs[0].String()
		role := cmp.Or(p.tlsRoles[spiffe], p.config.TLS.DefaultAuthenticatedRole)
		claims := map[string]any{
			"role":   role,
			"sub":    peer.Subject.String(),
			"iss":    peer.Issuer.String(),
			"spiffe": strings.TrimPrefix(spiffe, "spiffe://"),
		}
		if len(peer.EmailAddresses) > 0 {
			claims["email"] = peer.EmailAddresses[0]
		}
		logger.KV(xlog.DEBUG, "spiffe", spiffe, "role", role)
		return identity.NewIdentity(role, peer.Subject.CommonName, "", claims, "", "", identity.MethodCertificate), nil
	}

	logger.KV(xlog.DEBUG, "spiffe", "none", "cn", peer.Subject.CommonName)
	return nil, errors.Errorf("could not determine identity: %q", peer.Subject.CommonName)
}
