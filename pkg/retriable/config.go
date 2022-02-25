package retriable

import (
	"os"
	"time"

	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// Config of the client
type Config struct {
	Clients map[string]ClientConfig `json:"clients,omitempty" yaml:"clients,omitempty"`
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
	cfg Config
}

// NewFactory returns new Factory
func NewFactory(cfg Config) (*Factory, error) {
	return &Factory{
		cfg: cfg,
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

// CreateClient return Client for a specified client name.
// If the name is not found in the configuration,
// a client with default settings will be returned.
func (f *Factory) CreateClient(clientName string) (*Client, error) {
	if cfg, ok := f.cfg.Clients[clientName]; ok {
		return Create(cfg)
	}
	return New(), nil
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
