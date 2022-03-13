package retriable

import (
	"crypto"
	"os"
	"path"
	"strings"
	"time"

	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/yaml.v2"
)

const (
	authTokenFileName = ".auth_token"
)

// Config of the client
type Config struct {
	Clients map[string]*ClientConfig `json:"clients,omitempty" yaml:"clients,omitempty"`
}

// ClientConfig of the client, per specific host
type ClientConfig struct {
	Hosts []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`

	// TLS provides TLS config for the client
	TLS *TLSInfo `json:"tls,omitempty" yaml:"tls,omitempty"`

	// Request provides Request Policy
	Request *RequestPolicy `json:"request,omitempty" yaml:"request,omitempty"`

	// StorageFolder for keys and token.
	StorageFolder string `json:"storage_folder,omitempty" yaml:"storage_folder,omitempty"`

	// EnvNameAuthToken specifies os.Env name for the Authorization token.
	// if the token is DPoP, then a correponding JWK must be found in StorageFolder
	EnvAuthTokenName string `json:"auth_token_env_name,omitempty" yaml:"auth_token_env_name,omitempty"`
}

// RequestPolicy contains configuration info for Request policy
type RequestPolicy struct {
	RetryLimit int           `json:"retry_limit,omitempty" yaml:"retry_limit,omitempty"`
	Timeout    time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// TLSInfo contains configuration info for the TLS
type TLSInfo struct {
	// CertFile specifies location of the cert
	CertFile string `json:"cert,omitempty" yaml:"cert,omitempty"`

	// KeyFile specifies location of the key
	KeyFile string `json:"key,omitempty" yaml:"key,omitempty"`

	// TrustedCAFile specifies location of the trusted Root file
	TrustedCAFile string `json:"trusted_ca,omitempty" yaml:"trusted_ca,omitempty"`
}

// Factory provides factory for retriable client for a specific host
type Factory struct {
	cfg     Config
	perHost map[string]*ClientConfig
}

// NewFactory returns new Factory
func NewFactory(cfg Config) (*Factory, error) {
	perHost := map[string]*ClientConfig{}
	for _, c := range cfg.Clients {
		for _, host := range c.Hosts {
			if perHost[host] != nil {
				return nil, errors.Errorf("multiple entries for host: %s", host)
			}
			perHost[host] = c
		}
	}

	return &Factory{
		cfg:     cfg,
		perHost: perHost,
	}, nil
}

// LoadFactory returns new Factory
func LoadFactory(file string) (*Factory, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load config")
	}
	var cfg Config
	err = yaml.Unmarshal(f, &cfg)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to parse config")
	}

	return NewFactory(cfg)
}

// CreateClient returns Client for a specified client name.
// If the name is not found in the configuration,
// a client with default settings will be returned.
func (f *Factory) CreateClient(clientName string) (*Client, error) {
	if cfg, ok := f.cfg.Clients[clientName]; ok {
		return Create(*cfg)
	}
	return New(), nil
}

// ForHost returns Client for specified host name.
// If the name is not found in the configuration,
// a client with default settings will be returned.
func (f *Factory) ForHost(hostname string) (*Client, error) {
	if cfg, ok := f.perHost[hostname]; ok {
		logger.KV(xlog.TRACE, "host", hostname, "cfg", cfg)
		return Create(*cfg)
	}
	logger.KV(xlog.TRACE, "reason", "config_not_found", "host", hostname)
	return New(WithHosts([]string{hostname})), nil
}

// LoadClient returns new Client
func LoadClient(file string) (*Client, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load config")
	}
	var cfg ClientConfig
	err = yaml.Unmarshal(f, &cfg)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to parse config")
	}

	return Create(cfg)
}

// Create returns new Client from provided config
func Create(cfg ClientConfig) (*Client, error) {
	opts := []ClientOption{
		WithEnvAuthTokenName(cfg.EnvAuthTokenName),
		WithStorageFolder(cfg.StorageFolder),
		WithHosts(cfg.Hosts),
	}

	if cfg.TLS != nil {
		tlscfg, err := tlsconfig.NewClientTLSFromFiles(
			cfg.TLS.CertFile,
			cfg.TLS.KeyFile,
			cfg.TLS.TrustedCAFile,
		)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to load TLS config")
		}
		opts = append(opts, WithTLS(tlscfg))
	}

	if cfg.Request != nil {
		pol := DefaultPolicy()
		pol.RequestTimeout = cfg.Request.Timeout
		pol.TotalRetryLimit = cfg.Request.RetryLimit
		opts = append(opts, WithPolicy(pol))
	}

	client := New(opts...)
	return client, nil
}

func loadAuthToken(dir string) (string, error) {
	file := path.Join(dir, ".auth_token")
	t, err := os.ReadFile(file)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return string(t), nil
}

func (c *Client) storeFolder() string {
	dir := c.StorageFolder
	if dir == "" {
		dirname, _ := os.UserHomeDir()
		dir = path.Join(dirname, ".config", "httpclient")
	}
	dir, _ = homedir.Expand(dir)
	return dir
}

// WithAuthorization sets Authorization token
func (c *Client) WithAuthorization() error {
	host := c.CurrentHost()
	// Allow to use Bearer only over TLS connection
	if !strings.HasPrefix(host, "https") &&
		!strings.HasPrefix(host, "unixs") {
		//return errors.Errorf("authorization header: tls required")
		return nil
	}
	tk := os.Getenv(c.EnvAuthTokenName)
	if tk == "" {
		tk, _ = loadAuthToken(c.storeFolder())
	}
	if tk == "" {
		return errors.Errorf("authorization: credentials not found")
	}

	ti := dpop.GetTokenInfo(tk)
	// check for DPoP
	if ti != nil && ti.CnfJkt != "" {
		k, _, err := c.LoadKey(ti.CnfJkt)
		if err != nil {
			return errors.WithMessage(err, "unable to load key for DPoP")
		}
		c.AddHeader(header.Authorization, "DPoP "+tk)
		c.signer, err = dpop.NewSigner(k.Key.(crypto.Signer))
		if err != nil {
			return errors.WithMessage(err, "unable to create signer")
		}
	} else {
		c.AddHeader(header.Authorization, "Bearer "+tk)
	}

	return nil
}

// StoreAuthToken persists auth token
func (c *Client) StoreAuthToken(token string) error {
	folder := c.storeFolder()
	os.MkdirAll(folder, 0755)
	err := os.WriteFile(path.Join(folder, authTokenFileName), []byte(token), 0600)
	if err != nil {
		return errors.WithMessagef(err, "unable to store token")
	}
	return nil
}

// LoadKey returns *jose.JSONWebKey
func (c *Client) LoadKey(label string) (*jose.JSONWebKey, string, error) {
	path := path.Join(c.storeFolder(), label+".jwk")
	return dpop.LoadKey(path)
}

// SaveKey saves the key to storage
func (c *Client) SaveKey(k *jose.JSONWebKey) (string, error) {
	return dpop.SaveKey(c.storeFolder(), k)
}
