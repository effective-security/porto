package rpcclient

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/pkg/retriable"
	"google.golang.org/grpc"
)

// Config for the client
type Config struct {
	// Endpoint of the server
	Endpoint string

	// DialTimeout is the timeout for failing to establish a connection.
	DialTimeout time.Duration

	// DialKeepAliveTime is the time after which client pings the server to see if
	// transport is alive.
	DialKeepAliveTime time.Duration

	// DialKeepAliveTimeout is the time that the client waits for a response for the
	// keep-alive probe. If the response is not received in this time, the connection is closed.
	DialKeepAliveTimeout time.Duration

	// TLS holds the client secure credentials, if any.
	TLS *tls.Config

	// DialOptions is a list of dial options for the grpc client (e.g., for interceptors).
	// For example, pass "grpc.WithBlock()" to block until the underlying connection is up.
	// Without this, Dial returns immediately and connecting the server happens in background.
	DialOptions []grpc.DialOption

	// CallOptions is a list of call options for the grpc client (e.g., for interceptors).
	CallOptions []grpc.CallOption

	// Context is the default client context; it can be used to cancel grpc dial out and
	// other operations that do not have an explicit context.
	Context context.Context

	// MaxRecvMsgSize sets the maximum message size that a client can send to the server.
	MaxRecvMsgSize int

	// MaxSendMsgSize sets the maximum message size that a server can send to the client.
	MaxSendMsgSize int

	StorageFolder    string
	EnvAuthTokenName string
	UserAgent        string

	CallerIdentity credentials.CallerIdentity
}

// LoadAuthToken returns AuthToken
func (c *Config) LoadAuthToken() (*retriable.AuthToken, string, error) {
	return c.Storage().LoadAuthToken()
}

// Storage returns the current storage
func (c *Config) Storage() *retriable.Storage {
	return retriable.OpenStorage(c.StorageFolder, c.Endpoint, c.EnvAuthTokenName)
}
