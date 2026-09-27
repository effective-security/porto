// Package rpcclient builds gRPC client connections from a Config: it wires
// transport credentials, per-RPC bearer/DPoP tokens (loaded from the
// environment or from a retriable.Storage folder), keepalive parameters,
// message size limits and an optional blocking dial with timeout.
//
// The Client owns a single *grpc.ClientConn that callers pass to the
// generated service constructors, together with Client.Opts() which holds
// the default call options (WaitForReady, MaxCallSendMsgSize,
// MaxCallRecvMsgSize):
//
//	cfg := &rpcclient.Config{
//		Endpoint:    "https://api.example.com:443",
//		TLS:         tlsCfg, // *tls.Config; nil dials without TLS
//		DialTimeout: 5 * time.Second,
//	}
//	if err := cfg.LoadAuthTokenOrFromEnv("MY_AUTH_TOKEN"); err != nil {
//		return err
//	}
//	client, err := rpcclient.New(cfg)
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	svc := pb.NewMyServiceClient(client.Conn())
//	res, err := svc.Call(ctx, req, client.Opts()...)
//
// Endpoint accepts https://, http://, unixs:///path and unix:///path, or a
// bare host[:port]. Host schemes are stripped and ":443" is appended when
// no port is given; Unix targets use gRPC's unix resolver. TLS and the
// Authorization token apply when TLS is configured and the endpoint uses
// the https:// or unixs:// scheme. New rejects TLS with any other endpoint;
// nil TLS dials without security.
//
// Config has no yaml/json tags and is populated programmatically. All
// constructors return errors rather than panic.
package rpcclient
