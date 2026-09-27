package rpcclient

import (
	"context"
	"crypto/tls"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/pkg/retriable"
	"google.golang.org/grpc"
)

// Config describes how to build a Client. It is populated programmatically
// (no yaml/json tags); only Endpoint is required.
type Config struct {
	// Endpoint of the server: https://host[:port], http://, unixs:///path,
	// unix:///path, or a bare host[:port]. ":443" is appended to host targets
	// when no port is given.
	Endpoint string

	// DialTimeout, when > 0, makes New block until the connection is Ready
	// or fail after this duration. Zero connects lazily in the background.
	DialTimeout time.Duration

	// DialKeepAliveTime is the time after which client pings the server to see if
	// transport is alive.
	DialKeepAliveTime time.Duration

	// DialKeepAliveTimeout is the time that the client waits for a response for the
	// keep-alive probe. If the response is not received in this time, the connection is closed.
	DialKeepAliveTimeout time.Duration

	// TLS holds the client TLS configuration. When set, Endpoint must start
	// with https:// or unixs://; otherwise New returns an error. CallerIdentity
	// and AuthToken are applied with TLS. A nil TLS dials without security.
	TLS *tls.Config

	// DialOptions is a list of extra dial options for the grpc client
	// (e.g., for interceptors), appended after the options derived from
	// this Config.
	DialOptions []grpc.DialOption

	// CallOptions, when set, replaces the default call options returned by
	// Client.Opts (WaitForReady and the message size limits).
	CallOptions []grpc.CallOption

	// Context is the default client context; it can be used to cancel grpc dial out and
	// other operations that do not have an explicit context.
	Context context.Context

	// MaxRecvMsgSize sets the maximum message size the client accepts from
	// the server (grpc.MaxCallRecvMsgSize); 0 means math.MaxInt32.
	MaxRecvMsgSize int

	// MaxSendMsgSize sets the maximum message size the client sends to the
	// server (grpc.MaxCallSendMsgSize); 0 means 10 MiB.
	MaxSendMsgSize int

	// StorageFolder is the retriable.Storage folder holding the
	// .auth_token file and DPoP keys; see Storage.
	StorageFolder string
	// UserAgent, when set, is sent as the gRPC user agent.
	UserAgent string

	// CallerIdentity, when set, supplies (and refreshes) the per-RPC
	// authorization token; it takes precedence over AuthToken.
	CallerIdentity credentials.CallerIdentity
	// AuthToken is a static token attached to every RPC, typically set by
	// LoadAuthToken or CheckAuthTokenFromEnv. DPoP tokens are signed with
	// the key named by DpopJkt from Storage.
	AuthToken *retriable.AuthToken
	// TokenLocation describes where AuthToken came from, for logging.
	TokenLocation string

	storage *retriable.Storage `json:"-" yaml:"-"`
}

// CheckAuthTokenFromEnv loads AuthToken from the named environment
// variable (see retriable.ParseAuthToken for the accepted formats).
// It returns false when the variable is unset or empty, and an error when
// the value is malformed or the token has expired.
func (c *Config) CheckAuthTokenFromEnv(env string) (bool, error) {
	val := os.Getenv(env)
	if val == "" {
		return false, nil
	}
	at, _, err := retriable.ParseAuthToken(val, "env://"+env)
	if err != nil {
		return true, errors.WithMessage(err, "invalid auth token")
	}
	if at.Expired() {
		return true, errors.New("auth token expired")
	}
	c.AuthToken = at
	c.TokenLocation = "env://" + env
	return true, nil
}

// LoadAuthTokenOrFromEnv sets AuthToken from the named environment variable
// when it is set, otherwise from the .auth_token file in Storage.
func (c *Config) LoadAuthTokenOrFromEnv(env string) error {
	ok, err := c.CheckAuthTokenFromEnv(env)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return c.LoadAuthToken()
}

// LoadAuthToken sets AuthToken and TokenLocation from the .auth_token file
// in Storage. It does not check expiry; New does.
func (c *Config) LoadAuthToken() error {
	at, location, err := c.Storage().LoadAuthToken()
	if err != nil {
		return err
	}
	c.AuthToken = at
	c.TokenLocation = location
	return nil
}

// Storage returns the token/key storage rooted at StorageFolder,
// creating it on first use.
func (c *Config) Storage() *retriable.Storage {
	if c.storage == nil {
		c.storage = retriable.NewStorage(c.StorageFolder)
	}
	return c.storage
}

// SetStorage replaces the storage returned by Storage.
func (c *Config) SetStorage(storage *retriable.Storage) {
	c.storage = storage
}
