package roles

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	tcredentials "github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/gigawattio/awsarn"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "roles")

const (
	// GuestRoleName defines role name for an unauthenticated user
	GuestRoleName = "guest"

	// TLSUserRoleName defines a generic role name for an authenticated user
	TLSUserRoleName = "tls_user"

	// JWTUserRoleName defines a generic role name for an authenticated user
	JWTUserRoleName = "jwt_user"

	// DPoPUserRoleName defines a generic role name for an authenticated user
	DPoPUserRoleName = "dpop_user"

	// AWSUserRoleName defines a generic role name for an authenticated user
	AWSUserRoleName = "aws_user"

	// DefaultSubjectClaim defines default JWT Subject claim
	DefaultSubjectClaim = "sub"

	// DefaultRoleClaim defines default Role claim
	DefaultRoleClaim = "email"

	// DefaultTenantClaim defines default Tenant claim
	DefaultTenantClaim = "tenant"

	awsTokenType = "AWS4"
)

// CacheTTL defines TTL for AWS cache
const CacheTTL = 5 * time.Minute

// IdentityProvider interface to extract identity from requests
type IdentityProvider interface {
	// ApplicableForRequest returns true if the provider is applicable for the request
	ApplicableForRequest(*http.Request) bool
	// IdentityFromRequest returns identity from the request
	IdentityFromRequest(*http.Request) (identity.Identity, error)

	// ApplicableForContext returns true if the provider is applicable for the request
	ApplicableForContext(ctx context.Context) bool
	// IdentityFromContext returns identity from the request
	IdentityFromContext(ctx context.Context, uri string) (identity.Identity, error)
}

// Provider for identity
type provider struct {
	config    IdentityMap
	dpopRoles map[string]string
	jwtRoles  map[string]string
	tlsRoles  map[string]string
	awsRoles  map[string]string
	jwt       jwt.Parser

	awsCache *expirable.LRU[string, *CallerIdentity]
}

// New returns Authz provider instance
func New(config *IdentityMap, jwt jwt.Parser) (IdentityProvider, error) {
	prov := &provider{
		config:    *config,
		dpopRoles: make(map[string]string),
		jwtRoles:  make(map[string]string),
		tlsRoles:  make(map[string]string),
		awsRoles:  make(map[string]string),
		jwt:       jwt,
		awsCache:  expirable.NewLRU[string, *CallerIdentity](100, nil, CacheTTL),
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
		prov.config.DPoP.SubjectClaim = values.StringsCoalesce(prov.config.DPoP.SubjectClaim, DefaultSubjectClaim)
		prov.config.DPoP.RoleClaim = values.StringsCoalesce(prov.config.DPoP.RoleClaim, DefaultRoleClaim)
		prov.config.DPoP.TenantClaim = values.StringsCoalesce(prov.config.DPoP.TenantClaim, DefaultTenantClaim)

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
		prov.config.JWT.SubjectClaim = values.StringsCoalesce(prov.config.JWT.SubjectClaim, DefaultSubjectClaim)
		prov.config.JWT.RoleClaim = values.StringsCoalesce(prov.config.JWT.RoleClaim, DefaultRoleClaim)
		prov.config.JWT.TenantClaim = values.StringsCoalesce(prov.config.JWT.TenantClaim, DefaultTenantClaim)

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

// ApplicableForRequest returns true if the provider is applicable for the request
func (p *provider) ApplicableForRequest(r *http.Request) bool {
	if (p.config.AWS.Enabled || p.config.DPoP.Enabled || p.config.JWT.Enabled) &&
		r.Header.Get(header.Authorization) != "" {
		return true
	}
	if p.config.TLS.Enabled && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return true
	}

	return false
}

// ApplicableForContext returns true if the provider is applicable for context
func (p *provider) ApplicableForContext(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	authorization := ok && len(md["authorization"]) > 0

	if authorization && (p.config.AWS.Enabled || p.config.DPoP.Enabled || p.config.JWT.Enabled) {
		return true
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

func tokenType(auth string) (token string, tokenType string) {
	if auth == "" {
		return
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) == 2 {
		tokenType = parts[0]
		token = parts[1]
	} else {
		token = auth
		tokenType = "Bearer"
	}
	return
}

// IdentityFromRequest returns identity from the request
func (p *provider) IdentityFromRequest(r *http.Request) (identity.Identity, error) {
	peers := getPeerCertAndCount(r)
	// logger.ContextKV(r.Context(), xlog.DEBUG,
	// 	"dpop_enabled", p.config.DPoP.Enabled,
	// 	"jwt_enabled", p.config.JWT.Enabled,
	// 	"tls_enabled", p.config.TLS.Enabled,
	// 	"certs_present", peers)

	authHeader := r.Header.Get(header.Authorization)
	token, typ := tokenType(authHeader)

	var err error
	var id identity.Identity

	if p.config.AWS.Enabled && strings.EqualFold(typ, awsTokenType) {
		id, err = p.awsIdentity(r.Context(), token, typ)
		if err != nil {
			logger.ContextKV(r.Context(), xlog.TRACE, "token", token, "err", err.Error())
			//return nil, err
		} else {
			return id, nil
		}
	}

	if p.config.DPoP.Enabled && strings.EqualFold(typ, "DPoP") {
		phdr := r.Header.Get(dpop.HTTPHeader)
		u := r.URL
		coreURL := url.URL{
			Scheme: values.StringsCoalesce(u.Scheme, "https"),
			Host:   values.StringsCoalesce(u.Host, r.Host),
			Path:   u.Path,
		}

		id, err = p.dpopIdentity(r.Context(), phdr, r.Method, coreURL.String(), token, "DPoP")
		if err != nil {
			logger.ContextKV(r.Context(), xlog.TRACE, "token", token, "err", err.Error())
			//return nil, err
		} else {
			return id, nil
		}
	}

	if p.config.JWT.Enabled && strings.EqualFold(typ, "Bearer") {
		id, err = p.jwtIdentity(r.Context(), token, typ)
		if err != nil {
			logger.ContextKV(r.Context(), xlog.TRACE, "token", token, "err", err.Error())
			//return nil, err
		} else {
			return id, nil
		}
	}

	if p.config.TLS.Enabled && peers > 0 {
		id, err = p.tlsIdentity(r.TLS)
		if err != nil {
			logger.ContextKV(r.Context(), xlog.TRACE, "reason", "tls", "err", err.Error())
		} else {
			return id, nil
		}
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

func dumpDM(md metadata.MD) []any {
	var res []any
	for k, v := range md {
		if len(v) > 0 {
			res = append(res, k, v[0])
		}
	}
	return res
}

// IdentityFromContext returns identity from context
func (p *provider) IdentityFromContext(ctx context.Context, uri string) (identity.Identity, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok && len(md[tcredentials.TokenFieldNameGRPC]) > 0 {
		token, typ := tokenType(md[tcredentials.TokenFieldNameGRPC][0])

		if p.config.DebugLogs {
			logger.ContextKV(ctx, xlog.DEBUG,
				"uri", uri,
				"token_type", typ,
			)
			logger.ContextKV(ctx, xlog.DEBUG, dumpDM(md)...)
		}

		if p.config.AWS.Enabled &&
			strings.EqualFold(typ, awsTokenType) {
			id, err := p.awsIdentity(ctx, token, typ)
			if err == nil {
				return id, nil
			}
			logger.ContextKV(ctx, xlog.WARNING, "err", err.Error())
		}

		dhdr := md["dpop"]
		if p.config.DPoP.Enabled &&
			strings.EqualFold(typ, "DPoP") && len(dhdr) > 0 {
			id, err := p.dpopIdentity(ctx, dhdr[0], "POST", uri, token, "DPoP")
			if err == nil {
				return id, nil
			}
		}

		if p.config.JWT.Enabled && typ != "" {
			id, err := p.jwtIdentity(ctx, token, typ)
			if err == nil {
				return id, nil
			}
		}
		logger.ContextKV(ctx, xlog.DEBUG, "reason", "no_token_found")
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
					logger.ContextKV(ctx, xlog.DEBUG, "type", "TLS", "role", id)
					return id, nil
				}
			}
		}
	}
	if p.config.DebugLogs {
		logger.ContextKV(ctx, xlog.DEBUG, "role", "guest")
	}
	return identity.GuestIdentityForContext(ctx, uri)
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
	return identity.NewIdentity(role, subj, tenant, claims, auth, tokenType), nil
}

func (p *provider) awsIdentity(ctx context.Context, auth, tokenType string) (identity.Identity, error) {
	u, err := base64.RawURLEncoding.DecodeString(auth)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid AWS4 token")
	}
	url := string(u)
	ci, ok := p.awsCache.Get(url)
	if !ok {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		r.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to get Caller Identity from AWS")
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to decode AWS response")
		}

		if resp.StatusCode != http.StatusOK {
			logger.ContextKV(ctx, xlog.DEBUG,
				//"url", url,
				"body", string(body))
			return nil, errors.WithMessagef(err, "failed to get Caller Identity from AWS: %s", resp.Status)
		}

		ci = new(CallerIdentity)
		err = json.Unmarshal(body, &ci)
		if err != nil {
			logger.KV(xlog.DEBUG,
				"body", string(body),
				"err", err.Error(),
			)
			return nil, errors.WithMessage(err, "failed to decode AWS response")
		}
		p.awsCache.Add(url, ci)
	}

	callerIdentity := ci.GetCallerIdentityResponse.GetCallerIdentityResult
	acc := callerIdentity.Account
	if len(p.config.AWS.AllowedAccounts) > 0 && !slices.ContainsString(p.config.AWS.AllowedAccounts, acc) {
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

	role := values.StringsCoalesce(p.awsRoles[subj], p.awsRoles[callerIdentity.Arn], p.config.AWS.DefaultAuthenticatedRole)
	logger.KV(xlog.DEBUG,
		"account", callerIdentity.Account,
		"arn", callerIdentity.Arn,
		"user", callerIdentity.UserID,
		"role", role,
	)
	return identity.NewIdentity(role, subj, callerIdentity.Account, claims, auth, tokenType), nil
}

// CallerIdentity represents the Identity of the caller
// AWS Caller Identity Response documentation: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
type CallerIdentity struct {
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
}

func (p *provider) jwtIdentity(ctx context.Context, auth, tokenType string) (identity.Identity, error) {
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
		return nil, errors.WithMessage(err, "unable to parse JWT token")
	}

	email := claims.String("email")
	subj := claims.String(p.config.JWT.SubjectClaim)
	tenant := claims.String(p.config.JWT.TenantClaim)
	roleClaim := claims.String(p.config.JWT.RoleClaim)
	role := values.StringsCoalesce(p.jwtRoles[roleClaim], p.config.JWT.DefaultAuthenticatedRole)
	logger.KV(xlog.DEBUG,
		"role", role,
		"tenant", tenant,
		"subject", subj,
		"email", email,
		"type", tokenType)
	return identity.NewIdentity(role, subj, tenant, claims, auth, tokenType), nil
}

func (p *provider) tlsIdentity(TLS *tls.ConnectionState) (identity.Identity, error) {
	peer := TLS.PeerCertificates[0]
	if len(peer.URIs) == 1 && peer.URIs[0].Scheme == "spiffe" {
		spiffe := peer.URIs[0].String()
		role := values.StringsCoalesce(p.tlsRoles[spiffe], p.config.TLS.DefaultAuthenticatedRole)
		claims := map[string]interface{}{
			"role":   role,
			"sub":    peer.Subject.String(),
			"iss":    peer.Issuer.String(),
			"spiffe": strings.TrimPrefix(spiffe, "spiffe://"),
		}
		if len(peer.EmailAddresses) > 0 {
			claims["email"] = peer.EmailAddresses[0]
		}
		logger.KV(xlog.DEBUG, "spiffe", spiffe, "role", role)
		return identity.NewIdentity(role, peer.Subject.CommonName, "", claims, "", ""), nil
	}

	logger.KV(xlog.DEBUG, "spiffe", "none", "cn", peer.Subject.CommonName)
	return nil, errors.Errorf("could not determine identity: %q", peer.Subject.CommonName)
}
