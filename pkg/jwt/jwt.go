package jwt

import (
	"encoding/json"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/effective-security/porto/x/fileutil"
	"github.com/effective-security/xlog"
	"github.com/go-phorce/dolly/xpki/certutil"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "jwt")

// Signer specifies JWT signer interface
type Signer interface {
	// SignToken returns signed JWT token
	SignToken(id, subject, audience string, expiry time.Duration) (string, *jwt.StandardClaims, error)
}

// Parser specifies JWT parser interface
type Parser interface {
	// ParseToken returns jwt.StandardClaims
	ParseToken(authorization, audience string) (*jwt.StandardClaims, error)
}

// Provider specifies JWT provider interface
type Provider interface {
	Signer
	Parser
}

// Key for JWT signature
type Key struct {
	// ID of the key
	ID   string `json:"id" yaml:"id"`
	Seed string `json:"seed" yaml:"seed"`
}

// Config provides OAuth2 configuration
type Config struct {
	// Issuer specifies issuer claim
	Issuer string `json:"issuer" yaml:"issuer"`
	// KeyID specifies ID of the current key
	KeyID string `json:"kid" yaml:"kid"`
	// Keys specifies list of issuer's keys
	Keys []*Key `json:"keys" yaml:"keys"`
}

// provider for JWT
type provider struct {
	issuer string
	kid    string
	keys   map[string][]byte
}

// LoadConfig returns configuration loaded from a file
func LoadConfig(file string) (*Config, error) {
	if file == "" {
		return &Config{}, nil
	}

	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var config Config
	if strings.HasSuffix(file, ".json") {
		err = json.Unmarshal(raw, &config)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to unmarshal JSON: %q", file)
		}
	} else {
		err = yaml.Unmarshal(raw, &config)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to unmarshal YAML: %q", file)
		}
	}

	if config.KeyID == "" {
		return nil, errors.Errorf("missing kid: %q", file)
	}
	if len(config.Keys) == 0 {
		return nil, errors.Errorf("missing keys: %q", file)
	}

	return &config, nil
}

// Load returns new provider
func Load(cfgfile string) (Provider, error) {
	cfg, err := LoadConfig(cfgfile)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return New(cfg), nil
}

// New returns new provider
func New(cfg *Config) Provider {
	p := &provider{
		issuer: cfg.Issuer,
		kid:    cfg.KeyID,
		keys:   map[string][]byte{},
	}

	if p.issuer == "" {
		logger.Panic("issuer not configured")
	}

	if len(cfg.Keys) == 0 {
		logger.Panic("keys not provided")
	}

	for _, key := range cfg.Keys {
		seed, err := fileutil.LoadConfigWithSchema(key.Seed)
		if err != nil {
			logger.Panic("failed to load seed: " + err.Error())
		}
		p.keys[key.ID] = certutil.SHA256([]byte(seed))
	}

	if p.kid == "" {
		p.kid = cfg.Keys[len(cfg.Keys)-1].ID
	}

	return p
}

// CurrentKey returns the key currently being used to sign tokens.
func (p *provider) currentKey() (string, []byte) {
	if key, ok := p.keys[p.kid]; ok {
		return p.kid, key
	}
	return "", nil
}

// SignToken returns signed JWT token with custom claims
func (p *provider) SignToken(id, subject, audience string, expiry time.Duration) (string, *jwt.StandardClaims, error) {
	kid, key := p.currentKey()
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)
	claims := &jwt.StandardClaims{
		Id:        id,
		ExpiresAt: expiresAt.Unix(),
		Issuer:    p.issuer,
		IssuedAt:  now.Unix(),
		Audience:  audience,
		Subject:   subject,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = kid

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", nil, errors.WithMessagef(err, "failed to sign token")
	}

	return tokenString, claims, nil
}

// ParseToken returns jwt.StandardClaims
func (p *provider) ParseToken(authorization, audience string) (*jwt.StandardClaims, error) {
	claims := &jwt.StandardClaims{
		Issuer:   p.issuer,
		Audience: audience,
	}

	token, err := jwt.ParseWithClaims(authorization, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		if kid, ok := token.Header["kid"]; ok {
			var id string
			switch t := kid.(type) {
			case string:
				id = t
			case int:
				id = strconv.Itoa(t)
			}

			if key, ok := p.keys[id]; ok {
				return key, nil
			}
			return nil, errors.Errorf("unexpected kid")
		}
		return nil, errors.Errorf("missing kid")
	})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to verify token")
	}

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		if claims.Issuer != p.issuer {
			return nil, errors.Errorf("invalid issuer: %s", claims.Issuer)
		}
		if audience != "" && claims.Audience != audience {
			return nil, errors.Errorf("invalid audience: %s", claims.Audience)
		}

		return claims, nil
	}

	return nil, errors.Errorf("invalid token")
}
