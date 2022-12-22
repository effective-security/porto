package roles

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"

	tcredentials "github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/x/slices"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
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

	// DefaultSubjectClaim defines default JWT Subject claim
	DefaultSubjectClaim = "sub"

	// DefaultRoleClaim defines default Role claim
	DefaultRoleClaim = "email"

	// DefaultTenantClaim defines default Tenant claim
	DefaultTenantClaim = "tenant"
)

// IdentityProvider interface to extract identity from requests
type IdentityProvider interface {
	// ApplicableForRequest returns true if the provider is applicable for the request
	ApplicableForRequest(*http.Request) bool
	// IdentityFromRequest returns identity from the request
	IdentityFromRequest(*http.Request) (identity.Identity, error)

	// ApplicableForContext returns true if the provider is applicable for the request
	ApplicableForContext(ctx context.Context) bool
	// IdentityFromContext returns identity from the request
	IdentityFromContext(ctx context.Context) (identity.Identity, error)
}

// AccessToken provides interface for Access Token
type AccessToken interface {
	// Claims returns claims from the Access Token,
	// or nil if `auth` is not Access Token
	Claims(ctx context.Context, auth string) (jwt.MapClaims, error)
}

// Provider for identity
type provider struct {
	config    IdentityMap
	dpopRoles map[string]string
	jwtRoles  map[string]string
	tlsRoles  map[string]string
	jwt       jwt.Parser
	at        AccessToken
}

// New returns Authz provider instance
func New(config *IdentityMap, jwt jwt.Parser, at AccessToken) (IdentityProvider, error) {
	prov := &provider{
		config:    *config,
		dpopRoles: make(map[string]string),
		jwtRoles:  make(map[string]string),
		tlsRoles:  make(map[string]string),
		jwt:       jwt,
		at:        at,
	}

	if config.DPoP.Enabled {
		prov.config.DPoP.SubjectClaim = slices.StringsCoalesce(prov.config.DPoP.SubjectClaim, DefaultSubjectClaim)
		prov.config.DPoP.RoleClaim = slices.StringsCoalesce(prov.config.DPoP.RoleClaim, DefaultRoleClaim)
		prov.config.DPoP.TenantClaim = slices.StringsCoalesce(prov.config.DPoP.TenantClaim, DefaultTenantClaim)

		for role, users := range config.DPoP.Roles {
			for _, user := range users {
				prov.dpopRoles[user] = role
			}
		}
	}
	if config.JWT.Enabled {
		prov.config.JWT.SubjectClaim = slices.StringsCoalesce(prov.config.JWT.SubjectClaim, DefaultSubjectClaim)
		prov.config.JWT.RoleClaim = slices.StringsCoalesce(prov.config.JWT.RoleClaim, DefaultRoleClaim)
		prov.config.JWT.TenantClaim = slices.StringsCoalesce(prov.config.JWT.TenantClaim, DefaultTenantClaim)

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
	if (p.config.DPoP.Enabled || p.config.JWT.Enabled) &&
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
	// TODO: DPoP over gRPC
	if p.config.JWT.Enabled {
		md, ok := metadata.FromIncomingContext(ctx)
		if ok && len(md["authorization"]) > 0 {
			return true
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

	if p.config.DPoP.Enabled {
		if strings.EqualFold(typ, "DPoP") {
			id, err := p.dpopIdentity(r, token, "DPoP")
			if err != nil {
				logger.ContextKV(r.Context(), xlog.TRACE, "token", token, "err", err.Error())
				return nil, err
			}
			return id, nil
		}
	}

	if p.config.JWT.Enabled {
		if strings.EqualFold(typ, "Bearer") {
			id, err := p.jwtIdentity(token, "Bearer")
			if err != nil {
				logger.ContextKV(r.Context(), xlog.TRACE, "token", token, "err", err.Error())
				return nil, err
			}
			return id, nil
		}
	}

	if p.config.TLS.Enabled && peers > 0 {
		id, err := p.tlsIdentity(r.TLS)
		if err == nil {
			logger.ContextKV(r.Context(), xlog.DEBUG, "type", "TLS", "role", id)
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
func (p *provider) IdentityFromContext(ctx context.Context) (identity.Identity, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if p.config.DebugLogs {
			logger.ContextKV(ctx, xlog.DEBUG, dumpDM(md)...)
		}
		if p.config.JWT.Enabled && len(md[tcredentials.TokenFieldNameGRPC]) > 0 {
			if token, typ := tokenType(md[tcredentials.TokenFieldNameGRPC][0]); typ != "" {
				return p.jwtIdentity(token, typ)
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
	return identity.GuestIdentityForContext(ctx)
}

func (p *provider) dpopIdentity(r *http.Request, auth, tokenType string) (identity.Identity, error) {
	res, err := dpop.VerifyClaims(dpop.VerifyConfig{}, r)
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
	if p.at != nil {
		claims, err = p.at.Claims(r.Context(), auth)
		if err != nil {
			return nil, err
		}
		if claims != nil {
			err = claims.Valid(cfg)
		}
	}
	if claims == nil {
		claims, err = p.jwt.ParseToken(auth, cfg)
	}
	if err != nil {
		return nil, err
	}

	tb, err := dpop.GetCnfClaim(claims)
	if err != nil {
		return nil, err
	}
	if tb != res.Thumbprint {
		logger.ContextKV(r.Context(), xlog.DEBUG, "header", tb, "claims", res.Thumbprint)
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

	logger.ContextKV(r.Context(), xlog.DEBUG,
		"role", role,
		"tenant", tenant,
		"subject", subj,
		"email", email,
		"type", tokenType)
	return identity.NewIdentity(role, subj, tenant, claims, auth, tokenType), nil
}

func (p *provider) jwtIdentity(auth, tokenType string) (identity.Identity, error) {
	var claims jwt.MapClaims
	var err error

	cfg := jwt.VerifyConfig{
		ExpectedIssuer: p.config.JWT.Issuer,
	}
	if p.config.JWT.Audience != "" {
		cfg.ExpectedAudience = []string{p.config.JWT.Audience}
	}
	if p.at != nil {
		claims, err = p.at.Claims(context.Background(), auth)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to extract claims from access token")
		}
		if claims != nil {
			err = claims.Valid(cfg)
			if err != nil {
				return nil, err
			}
		}
	}
	if claims == nil {
		claims, err = p.jwt.ParseToken(auth, cfg)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to parse JWT token")
		}
	}

	email := claims.String("email")
	subj := claims.String(p.config.JWT.SubjectClaim)
	tenant := claims.String(p.config.JWT.TenantClaim)
	roleClaim := claims.String(p.config.JWT.RoleClaim)
	role := p.jwtRoles[roleClaim]
	if role == "" {
		role = p.config.JWT.DefaultAuthenticatedRole
	}
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
		role := p.tlsRoles[spiffe]
		if role == "" {
			role = p.config.TLS.DefaultAuthenticatedRole
		}
		logger.KV(xlog.DEBUG, "spiffe", spiffe, "role", role)
		claims := map[string]interface{}{
			"sub":    peer.Subject.String(),
			"iss":    peer.Issuer.String(),
			"spiffe": spiffe,
		}
		if len(peer.EmailAddresses) > 0 {
			claims["email"] = peer.EmailAddresses[0]
		}
		return identity.NewIdentity(role, peer.Subject.CommonName, "", claims, "", ""), nil
	}

	logger.KV(xlog.DEBUG, "spiffe", "none", "cn", peer.Subject.CommonName)

	return nil, errors.Errorf("could not determine identity: %q", peer.Subject.CommonName)
}
