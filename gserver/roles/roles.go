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
	TLSUserRoleName = "tls_authenticated"

	// JWTUserRoleName defines a generic role name for an authenticated user
	JWTUserRoleName = "jwt_authenticated"

	// DPoPUserRoleName defines a generic role name for an authenticated user
	DPoPUserRoleName = "dpop_authenticated"
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

// Provider for identity
type provider struct {
	config    IdentityMap
	dpopRoles map[string]string
	jwtRoles  map[string]string
	tlsRoles  map[string]string
	jwt       jwt.Parser
}

// New returns Authz provider instance
func New(config *IdentityMap, jwt jwt.Parser) (IdentityProvider, error) {
	prov := &provider{
		config:    *config,
		dpopRoles: make(map[string]string),
		jwtRoles:  make(map[string]string),
		tlsRoles:  make(map[string]string),
		jwt:       jwt,
	}

	if config.DPoP.Enabled {
		for role, users := range config.DPoP.Roles {
			for _, user := range users {
				prov.dpopRoles[user] = role
			}
		}
	}
	if config.JWT.Enabled {
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

// IdentityFromRequest returns identity from the request
func (p *provider) IdentityFromRequest(r *http.Request) (identity.Identity, error) {
	peers := getPeerCertAndCount(r)
	logger.KV(xlog.DEBUG,
		"dpop_enabled", p.config.DPoP.Enabled,
		"jwt_enabled", p.config.JWT.Enabled,
		"tls_enabled", p.config.TLS.Enabled,
		"certs_present", peers)

	authHeader := r.Header.Get(header.Authorization)
	if p.config.DPoP.Enabled {
		if strings.ToLower(slices.StringUpto(authHeader, 5)) == "dpop " {
			token := authHeader[5:]
			id, err := p.dpopIdentity(r, token)
			if err != nil {
				logger.KV(xlog.TRACE, "token", token, "err", err.Error())
				return nil, errors.WithStack(err)
			}
			return id, nil
		}
	}

	if p.config.JWT.Enabled {
		if strings.ToLower(slices.StringUpto(authHeader, 7)) == "bearer " {
			token := authHeader[7:]
			id, err := p.jwtIdentity(token)
			if err != nil {
				logger.KV(xlog.TRACE, "token", token, "err", err.Error())
				return nil, errors.WithStack(err)
			}
			return id, nil
		}
	}

	if p.config.TLS.Enabled && peers > 0 {
		id, err := p.tlsIdentity(r.TLS)
		if err == nil {
			logger.Debugf("type=TLS, role=%v", id)
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

// IdentityFromContext returns identity from context
func (p *provider) IdentityFromContext(ctx context.Context) (identity.Identity, error) {
	if p.config.JWT.Enabled {
		md, ok := metadata.FromIncomingContext(ctx)
		if ok && len(md[tcredentials.TokenFieldNameGRPC]) > 0 {
			return p.jwtIdentity(md[tcredentials.TokenFieldNameGRPC][0])
		}
	}

	if p.config.TLS.Enabled {
		c, ok := peer.FromContext(ctx)
		if ok {
			si, ok := c.AuthInfo.(credentials.TLSInfo)
			if ok && len(si.State.PeerCertificates) > 0 {
				id, err := p.tlsIdentity(&si.State)
				if err == nil {
					logger.Debugf("type=TLS, role=%v", id)
					return id, nil
				}
			}
		}
	}
	return identity.GuestIdentityForContext(ctx)
}

func (p *provider) dpopIdentity(r *http.Request, auth string) (identity.Identity, error) {
	res, err := dpop.VerifyClaims(dpop.VerifyConfig{}, r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	cfg := &jwt.VerifyConfig{
		ExpectedAudience: p.config.JWT.Audience,
	}
	claims, err := p.jwt.ParseToken(auth, cfg)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	m, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return nil, errors.Errorf("dpop: invalid cnf claim")
	}
	if tb, ok := m[dpop.CnfThumbprint].(string); !ok || tb != res.Thumbprint {
		logger.Debugf("header=%s, claims=%s", m[dpop.CnfThumbprint], res.Thumbprint)
		return nil, errors.Errorf("dpop: thumbprint mismatch")
	}

	subj := claims.String("sub")
	role := p.jwtRoles[subj]
	if role == "" {
		role = p.config.DPoP.DefaultAuthenticatedRole
	}
	logger.Debugf("role=%s, subject=%s", role, subj)
	return identity.NewIdentity(role, subj, claims), nil
}

func (p *provider) jwtIdentity(auth string) (identity.Identity, error) {
	cfg := &jwt.VerifyConfig{
		ExpectedAudience: p.config.JWT.Audience,
	}
	claims, err := p.jwt.ParseToken(auth, cfg)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	subj := claims["sub"].(string)
	role := p.jwtRoles[subj]
	if role == "" {
		role = p.config.JWT.DefaultAuthenticatedRole
	}
	logger.Debugf("role=%s, subject=%s", role, subj)
	return identity.NewIdentity(role, subj, claims), nil
}

func (p *provider) tlsIdentity(TLS *tls.ConnectionState) (identity.Identity, error) {
	peer := TLS.PeerCertificates[0]
	if len(peer.URIs) == 1 && peer.URIs[0].Scheme == "spiffe" {
		spiffe := peer.URIs[0].String()
		role := p.tlsRoles[spiffe]
		if role == "" {
			role = p.config.TLS.DefaultAuthenticatedRole
		}
		logger.Debugf("spiffe=%s, role=%s", spiffe, role)
		claims := map[string]interface{}{
			"sub": peer.Subject.String(),
			"iss": peer.Issuer.String(),
		}
		if len(peer.EmailAddresses) > 0 {
			claims["email"] = peer.EmailAddresses[0]
		}
		return identity.NewIdentity(role, peer.Subject.CommonName, claims), nil
	}

	logger.Debugf("spiffe=none, cn=%q", peer.Subject.CommonName)

	return nil, errors.Errorf("could not determine identity: %q", peer.Subject.CommonName)
}
