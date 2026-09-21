// Package transport provides net.Listener wrappers for servers: a TLS
// listener that performs the handshake eagerly with optional CRL checking,
// and keepalive listeners that enable TCP keepalive on accepted connections.
//
// TLSInfo holds the file-based TLS settings for a server and builds a
// tls.Config whose certificate is rotated by a tlsconfig.KeypairReloader
// (polling every 5 minutes). Only CertFile, KeyFile, TrustedCAFile,
// ClientCAFile, ClientAuthType, CipherSuites, CRLVerifier and
// HandshakeFailure are used by this package; the remaining fields are
// retained for configuration compatibility and are not enforced.
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
//		return err
//	}
//	srv := &http.Server{Handler: h, TLSConfig: info.Config()}
//	return srv.Serve(tlsLn)
//
// NewKeepAliveListener wraps a listener so accepted TCP connections get a
// 30s keepalive; with scheme "https" it also wraps connections with
// tls.Server (lazy handshake) using the supplied tls.Config.
package transport
