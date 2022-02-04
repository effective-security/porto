package roles

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"

	tcredentials "github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
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
	config   IdentityMap
	jwtRoles map[string]string
	tlsRoles map[string]string
	jwt      jwt.Parser
}

// New returns Authz provider instance
func New(config *IdentityMap, jwt jwt.Parser) (IdentityProvider, error) {
	prov := &provider{
		config:   *config,
		jwtRoles: make(map[string]string),
		tlsRoles: make(map[string]string),
		jwt:      jwt,
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
	if p.config.JWT.Enabled {
		key := r.Header.Get(header.Authorization)
		if key != "" && strings.HasPrefix(key, header.Bearer) {
			return true
		}
	}
	if p.config.TLS.Enabled && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return true
	}

	return false
}

// ApplicableForContext returns true if the provider is applicable for context
func (p *provider) ApplicableForContext(ctx context.Context) bool {
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
		"jwt_enabled", p.config.JWT.Enabled,
		"tls_enabled", p.config.TLS.Enabled,
		"certs_present", peers)

	if p.config.JWT.Enabled {
		key := r.Header.Get(header.Authorization)
		if key != "" && strings.HasPrefix(key, header.Bearer) {
			return p.jwtIdentity(key[7:])
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
	return identity.NewIdentity(role, subj, ""), nil
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
		return identity.NewIdentity(role, peer.Subject.CommonName, ""), nil
	}

	logger.Debugf("spiffe=none, cn=%q", peer.Subject.CommonName)

	return nil, errors.Errorf("could not determine identity: %q", peer.Subject.CommonName)
}