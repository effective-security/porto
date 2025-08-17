package retriable

import (
	"crypto"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// Config of the client
type Config struct {
	Clients map[string]*ClientConfig `json:"clients,omitempty" yaml:"clients,omitempty"`
}

// ClientConfig of the client, per specific host
type ClientConfig struct {
	Host string `json:"host" yaml:"host"`

	// TLS provides TLS config for the client
	TLS *TLSInfo `json:"tls,omitempty" yaml:"tls,omitempty"`

	// Request provides Request Policy
	Request *RequestPolicy `json:"request,omitempty" yaml:"request,omitempty"`

	// StorageFolder specifies the root folder for keys and token.
	StorageFolder string `json:"storage_folder,omitempty" yaml:"storage_folder,omitempty"`

	// AuthToken specifies the access token
	AuthToken *AuthToken `json:"-" yaml:"-"`

	// TokenLocation specifies the location of the token
	TokenLocation string `json:"-" yaml:"-"`

	storage *Storage `json:"-" yaml:"-"`
}

func (c *ClientConfig) Storage() *Storage {
	if c.storage == nil {
		c.storage = OpenStorage(c.StorageFolder, c.Host)
	}
	return c.storage
}

// LoadAuthToken returns AuthToken
// returns AuthToken, location, error
func (c *ClientConfig) LoadAuthToken() error {
	storage := c.Storage()
	if storage == nil {
		return errors.Errorf("authorization: storage not found")
	}
	at, location, err := storage.LoadAuthToken()
	if err != nil {
		return err
	}
	c.AuthToken = at
	c.TokenLocation = location
	return nil
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
	for name, c := range cfg.Clients {
		if c.Host == "" {
			return nil, errors.Errorf("invalid configuration: missing host: %s", name)
		}
		perHost[c.Host] = c
	}

	return &Factory{
		cfg:     cfg,
		perHost: perHost,
	}, nil
}

// LoadFactory returns new Factory
func LoadFactory(file string) (*Factory, error) {
	file, _ = homedir.Expand(file)

	f, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load config")
	}
	var cfg Config
	err = yaml.Unmarshal(f, &cfg)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse config: %s", file)
	}

	return NewFactory(cfg)
}

// CreateClient returns Client for a specified client name.
// If the name is not found in the configuration,
// a client with default settings will be returned.
func (f *Factory) CreateClient(clientName string) (*Client, error) {
	if cfg, ok := f.cfg.Clients[clientName]; ok {
		return New(*cfg)
	}
	return New(ClientConfig{})
}

// ConfigForHost returns config for host
func (f *Factory) ConfigForHost(hostname string) *ClientConfig {
	return f.perHost[hostname]
}

// ForHost returns Client for specified host name.
// If the name is not found in the configuration,
// a client with default settings will be returned.
func (f *Factory) ForHost(hostname string) (*Client, error) {
	if cfg, ok := f.perHost[hostname]; ok {
		logger.KV(xlog.TRACE, "host", hostname, "cfg", cfg)
		return New(*cfg)
	}
	logger.KV(xlog.DEBUG, "reason", "config_not_found", "host", hostname)
	return Default(hostname)
}

// New returns new Client
func NewForHost(cfg, host string) (*Client, error) {
	var rc *Client
	f, err := LoadFactory(cfg)
	if err == nil {
		rc, err = f.ForHost(host)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to create client")
		}
	}
	if rc == nil {
		rc, err = Default(host)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to create client")
		}
	}
	return rc, nil
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
		return nil, errors.WithMessagef(err, "failed to parse config: %s", file)
	}

	return New(cfg)
}

func (c *Client) WithStorage(storage *Storage) *Client {
	c.Config.storage = storage
	return c
}

// SetAuthorization sets Authorization token
func (c *Client) SetAuthorization() error {
	host := c.CurrentHost()
	// Allow to use Bearer only over TLS connection
	if !strings.HasPrefix(host, "https") &&
		!strings.HasPrefix(host, "unixs") {
		//return errors.Errorf("authorization header: tls required")
		return nil
	}

	if c.Config.AuthToken == nil {
		err := c.Config.LoadAuthToken()
		if err != nil {
			return err
		}
	}
	at := c.Config.AuthToken
	if at.Expired() {
		return errors.Errorf("authorization: token expired")
	}

	logger.KV(xlog.DEBUG,
		"token_location", c.Config.TokenLocation,
		"expires", at.Expires)

	if at.Expired() {
		return errors.Errorf("authorization: token expired")
	}

	if at.DpopJkt != "" {
		storage := c.Config.Storage()
		if storage == nil {
			return errors.Errorf("authorization: storage not found")
		}
		k, _, err := storage.LoadKey(at.DpopJkt)
		if err != nil {
			return errors.WithMessagef(err, "unable to load key for DPoP: %s", at.DpopJkt)
		}
		at.TokenType = "DPoP"
		c.dpopSigner, err = dpop.NewSigner(k.Key.(crypto.Signer))
		if err != nil {
			return errors.WithMessage(err, "unable to create DPoP signer")
		}
	}
	authHeader := at.AccessToken
	if at.TokenType != "" {
		authHeader = at.TokenType + " " + authHeader
	}
	c.AddHeader(header.Authorization, authHeader)

	return nil
}

// getValue returns a Query parameter
func getValue(vals url.Values, name string) string {
	v, ok := vals[name]
	if !ok || len(v) == 0 {
		return ""
	}
	return v[0]
}

// HostFolderName returns a folder name for a host
func HostFolderName(host string) string {
	u, err := url.Parse(host)
	if err == nil {
		host = u.Host
	}

	s := strings.NewReplacer(":", "_", "/", string(os.PathSeparator)).Replace(host)
	return strings.Trim(s, "_:/")
}
