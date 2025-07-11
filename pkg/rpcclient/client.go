package rpcclient

import (
	"context"
	"crypto"
	"math"
	"strings"

	tcredentials "github.com/effective-security/porto/gserver/credentials"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "rpcclient")

var (
	// client-side handling retrying of request failures where data was not written to the wire or
	// where server indicates it did not process the data. gRPC default is default is "FailFast(true)"
	defaultWaitForReady = grpc.WaitForReady(true)

	// client-side request send limit, gRPC default is math.MaxInt32
	// Make sure that "client-side send limit < server-side default send/recv limit"
	// Same value as "embed.DefaultMaxRequestBytes" plus gRPC overhead bytes
	defaultMaxCallSendMsgSize = 10 * 1024 * 1024

	// client-side response receive limit, gRPC default is 4MB
	// Make sure that "client-side receive limit >= server-side default send/recv limit"
	// because range response can easily exceed request send limits
	// Default to math.MaxInt32; writes exceeding server-side send limit fails anyway
	defaultMaxCallRecvMsgSize = math.MaxInt32
)

// Client provides and manages v1 client session.
type Client struct {
	cfg      Config
	conn     *grpc.ClientConn
	callOpts []grpc.CallOption

	ctx    context.Context
	cancel context.CancelFunc

	//lock sync.RWMutex
}

// NewFromURL creates a new client from a URL.
func NewFromURL(url string, skipAuth bool) (*Client, error) {
	return New(&Config{
		Endpoint: url,
	}, skipAuth)
}

// New creates a new client from a given configuration.
func New(cfg *Config, skipAuth bool) (*Client, error) {
	return newClient(cfg, skipAuth)
}

// Close shuts down the client's connections.
func (c *Client) Close() error {
	c.cancel()
	if c.conn != nil {
		return toErr(c.ctx, c.conn.Close())
	}
	return c.ctx.Err()
}

// Conn returns the current in-use connection
func (c *Client) Conn() *grpc.ClientConn {
	return c.conn
}

// Opts returns the current Call options
func (c *Client) Opts() []grpc.CallOption {
	return c.callOpts
}

func newClient(cfg *Config, skipAuth bool) (*Client, error) {
	if cfg == nil || len(cfg.Endpoint) == 0 {
		return nil, errors.Errorf("endpoint is required in client config")
	}

	// use a temporary skeleton client to bootstrap first connection
	baseCtx := context.Background()
	if cfg.Context != nil {
		baseCtx = cfg.Context
	}

	// defaultCallOpts defines a list of default "gRPC.CallOption".
	// Some options are exposed to "client.Config".
	// Defaults will be overridden by the settings in "client.Config".
	defaultCallOpts := []grpc.CallOption{
		defaultWaitForReady,
		grpc.MaxCallSendMsgSize(values.NumbersCoalesce(cfg.MaxSendMsgSize, defaultMaxCallSendMsgSize)),
		grpc.MaxCallRecvMsgSize(values.NumbersCoalesce(cfg.MaxRecvMsgSize, defaultMaxCallRecvMsgSize)),
	}

	ctx, cancel := context.WithCancel(baseCtx)
	client := &Client{
		conn:     nil,
		cfg:      *cfg,
		ctx:      ctx,
		cancel:   cancel,
		callOpts: defaultCallOpts,
	}

	if len(cfg.CallOptions) > 0 {
		// override default call options
		client.callOpts = cfg.CallOptions
	}

	dialEndpoint := cfg.Endpoint

	var dopts []grpc.DialOption
	var creds credentials.TransportCredentials

	if cfg.UserAgent != "" {
		dopts = append(dopts, grpc.WithUserAgent(cfg.UserAgent))
	}

	if cfg.TLS != nil &&
		(strings.HasPrefix(dialEndpoint, "https://") || strings.HasPrefix(dialEndpoint, "unixs://")) {

		bundle := tcredentials.NewBundle(tcredentials.Config{TLSConfig: cfg.TLS})
		creds = bundle.TransportCredentials()

		if cfg.CallerIdentity != nil {
			bundle.WithCallerIdentity(cfg.CallerIdentity)
		} else if !skipAuth {
			at, location, err := cfg.LoadAuthToken()
			logger.KV(xlog.DEBUG, "token_location", location)

			if err != nil {
				return nil, errors.WithMessage(err, "failed to load access token")
			}

			if at.Expired() {
				return nil, errors.Errorf("authorization: token expired")
			}
			// grpc: the credentials require transport level security
			token := at.AccessToken
			typ := values.StringsCoalesce(at.TokenType, "Bearer")
			if at.DpopJkt != "" {
				k, _, err := cfg.Storage().LoadKey(at.DpopJkt)
				if err != nil {
					return nil, errors.WithMessage(err, "unable to load key for DPoP")
				}
				typ = "DPoP"
				signer, err := dpop.NewSigner(k.Key.(crypto.Signer))
				if err != nil {
					return nil, errors.WithMessage(err, "unable to create DPoP signer")
				}
				bundle.WithDPoP(signer)
			}
			tok := tcredentials.Token{
				TokenType:   typ,
				AccessToken: token,
				Expires:     at.Expires,
			}
			bundle.UpdateAuthToken(tok)
		}
		dopts = append(dopts, grpc.WithPerRPCCredentials(bundle.PerRPCCredentials()))
	}

	logger.KV(xlog.TRACE, "dial", dialEndpoint)
	conn, err := client.dial(dialEndpoint, creds, dopts...)
	if err != nil {
		client.cancel()
		return nil, errors.WithStack(err)
	}

	client.conn = conn
	return client, nil
}

var removePrefix = strings.NewReplacer("https://", "", "http://", "", "unixs://", "", "unix://", "")

// dial configures and dials any grpc balancer target.
func (c *Client) dial(target string, creds credentials.TransportCredentials, dopts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts, err := c.dialSetupOpts(creds, dopts...)
	if err != nil {
		return nil, errors.Errorf("failed to configure dialer: %v", err)
	}

	opts = append(opts, c.cfg.DialOptions...)
	dctx := c.ctx

	if c.cfg.DialTimeout > 0 {
		opts = append(opts, grpc.WithBlock())

		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(c.ctx, c.cfg.DialTimeout)
		defer cancel()
	}

	target = removePrefix.Replace(target)
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	logger.KV(xlog.DEBUG, "target", target, "timeout", c.cfg.DialTimeout)

	conn, err := grpc.DialContext(dctx, target, opts...)
	if err != nil {
		return nil, err
	}

	logger.KV(xlog.DEBUG, "target", target, "status", "connecton_created")

	return conn, nil
}

// dialSetupOpts gives the dial opts prior to any authentication.
func (c *Client) dialSetupOpts(creds credentials.TransportCredentials, dopts ...grpc.DialOption) (opts []grpc.DialOption, err error) {
	if c.cfg.DialKeepAliveTime > 0 {
		params := keepalive.ClientParameters{
			Time:    c.cfg.DialKeepAliveTime,
			Timeout: c.cfg.DialKeepAliveTimeout,
		}
		opts = append(opts, grpc.WithKeepaliveParams(params))
	}
	opts = append(opts, dopts...)

	if creds == nil {
		creds = insecure.NewCredentials()
	}
	opts = append(opts, grpc.WithTransportCredentials(creds))

	return opts, nil
}

func toErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	code := httperror.GRPCCode(err)
	switch code {
	case codes.DeadlineExceeded:
		fallthrough
	case codes.Canceled:
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}
	return err
}

/*
func canceledByCaller(stopCtx context.Context, err error) bool {
	if stopCtx.Err() == nil || err == nil {
		return false
	}

	return err == context.Canceled || err == context.DeadlineExceeded
}
*/
