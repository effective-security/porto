// Package tlsconfig builds tls.Config values from PEM files and keeps the
// certificate fresh with a file-polling reloader.
//
// Entry points:
//
//   - NewServerTLSFromFiles / NewClientTLSFromFiles build a tls.Config with
//     MinVersion TLS 1.2 and ALPN "h2","http/1.1" from cert, key and optional
//     CA bundle files. An optional "<cert basename>.ocsp" file next to the
//     certificate is loaded as an OCSP staple if it is valid and not expired.
//   - KeypairReloader polls the cert/key files' modification times on a ticker
//     and reloads them (also forced once per hour). Use GetKeypairFunc as
//     tls.Config.GetCertificate on servers and GetClientCertificateFunc as
//     tls.Config.GetClientCertificate on clients.
//   - NewHTTPTransportWithReloader returns an http.RoundTripper whose client
//     certificate is swapped in on reload.
//   - UpdateCipherSuites maps cipher suite names to tls.Config.CipherSuites.
//     The names come from tls.CipherSuites; suites in tls.InsecureCipherSuites
//     and TLS 1.3 suites (not configurable in Go) are rejected.
//
// Server example:
//
//	cfg, err := tlsconfig.NewServerTLSFromFiles(certFile, keyFile, trustedCAFile, clientCAFile, tls.VerifyClientCertIfGiven)
//	if err != nil {
//		return err
//	}
//	reloader, err := tlsconfig.NewKeypairReloader("", certFile, keyFile, 5*time.Minute)
//	if err != nil {
//		return err
//	}
//	defer reloader.Close()
//	cfg.GetCertificate = reloader.GetKeypairFunc()
//	cfg.Certificates = nil // use the callback even when a client omits SNI
//
// Client example:
//
//	cfg, reloader, err := tlsconfig.NewClientTLSWithReloader(certFile, keyFile, rootsFile, 5*time.Minute)
//	if err != nil {
//		return err
//	}
//	defer reloader.Close()
//	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
//
// An expired certificate is rejected during reload. If the current
// certificate later expires, the GetCertificate and GetClientCertificate
// callbacks return an error instead of serving it.
package tlsconfig
