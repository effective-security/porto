// Package restserver provides an HTTP/HTTPS REST server that hosts a set of
// Service implementations behind a single httprouter-based mux.
//
// The server assembles a fixed middleware chain around the router
// (outermost first): trusted proxy policy, correlation ID, request
// metrics, identity mapping, a nested metrics handler that reports the
// caller role to the outer one, request logging, optional CORS (which answers
// preflights before authorization), optional path/role authorization
// (restserver/authz), readiness gating (restserver/ready), and finally the
// router. Custom chains can be supplied via WithMuxFactory; StartHTTP still
// applies the trusted proxy policy around them, and they must keep CORS
// outside authz themselves.
//
// By default the socket peer supplies the client IP and scheme.
// WithTrustedProxies accepts forwarding headers from the proxies in a policy
// built with identity.ParseTrustedProxies; the client IP is resolved once
// per request by identity.NewTrustedProxyHandler.
//
// Typical usage:
//
//	cfg := myConfig{bindAddr: ":8080", name: "WebAPI"} // implements restserver.Config
//	srv, err := restserver.New("v1.0.0", "", cfg, nil /* tlsConfig */)
//	if err != nil {
//		return err
//	}
//	trust, err := identity.ParseTrustedProxies([]string{"10.2.0.0/16"}) // optional
//	if err != nil {
//		return err
//	}
//	srv.WithCORS(&restserver.CORSOptions{AllowedOrigins: []string{"*"}}).
//		WithTrustedProxies(trust).
//		WithAuthz(authzProvider)          // optional
//	srv.AddService(mySvc)                 // implements restserver.Service
//	if err := srv.StartHTTP(); err != nil { // non-blocking, serves in a goroutine
//		return err
//	}
//	defer srv.StopHTTP()                  // drains requests, then closes services
//
// A Service registers its routes on the Router passed to Register:
//
//	func (s *mySvc) Register(r restserver.Router) {
//		r.GET("/v1/items/:id", func(w http.ResponseWriter, req *http.Request, p restserver.Params) {
//			marshal.WriteJSON(w, req, s.get(p.ByName("id")))
//		})
//	}
//
// Handlers are expected to write responses with xhttp/marshal and report
// failures as xhttp/httperror values.
package restserver
