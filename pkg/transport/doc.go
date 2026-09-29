// Package transport provides net.Listener wrappers for servers: a TLS
// listener that performs the handshake eagerly with optional CRL checking,
// and keepalive listeners that enable TCP keepalive on accepted connections.
//
// TLSInfo holds the file-based TLS settings for a server and builds a
// tls.Config whose certificate is rotated by a tlsconfig.KeypairReloader
// (polling every 5 minutes). A failed build caches nothing, so it can be
// retried. Client certificates are checked only by ClientAuthType and the
// optional CRLVerifier; for any other policy, set VerifyConnection on the
// config returned by ServerTLSWithReloader before serving (again after
// Close, which drops the config).
//
// Usage:
//
//	ln, err := net.Listen("tcp", ":8443")
//	if err != nil {
//		return err
//	}
//	info := &transport.TLSInfo{
//		CertFile:       "server.pem",
//		KeyFile:        "server-key.pem",
//		TrustedCAFile:  "ca.pem",
//		ClientAuthType: tls.VerifyClientCertIfGiven,
//		CRLVerifier:    verifier, // optional crlcache.Verifier
//	}
//	defer info.Close()
//
//	tlsLn, err := transport.NewTLSListener(ln, info) // handshakes in the background
//	if err != nil {
//		_ = ln.Close() // left open when the TLS config fails to load
//		return err
//	}
//	srv := &http.Server{Handler: h, TLSConfig: info.Config()}
//	return srv.Serve(tlsLn)
//
// NewKeepAliveListener wraps a listener so accepted TCP connections get
// keepalive probes after 30s idle, 15s apart, up to 9; with scheme "https"
// it also wraps connections with tls.Server (lazy handshake) using the
// supplied tls.Config.
//
// Both listeners return Accept errors of the wrapped listener to the caller
// unchanged, so servers such as net/http, grpc and cmux retry temporary
// errors (for example EMFILE). The TLS listener keeps accepting after an
// error and stops when the wrapped listener returns net.ErrClosed or when
// it is closed itself; always Close it.
package transport
