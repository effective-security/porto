// Package restserver provides an HTTP/HTTPS REST server that hosts a set of
// Service implementations behind a single httprouter-based mux.
//
// The server assembles a fixed middleware chain around the router
// (outermost first): correlation ID, identity mapping, request metrics,
// request logging, optional path/role authorization (restserver/authz),
// readiness gating (restserver/ready), and finally the router with an
// optional CORS wrapper. Custom chains can be supplied via WithMuxFactory.
//
// Typical usage:
//
//	cfg := myConfig{bindAddr: ":8080", name: "WebAPI"} // implements restserver.Config
//	srv, err := restserver.New("v1.0.0", "", cfg, nil /* tlsConfig */)
//	if err != nil {
//		return err
//	}
//	srv.WithCORS(&restserver.CORSOptions{AllowedOrigins: []string{"*"}}).
//		WithAuthz(authzProvider)          // optional
//	srv.AddService(mySvc)                 // implements restserver.Service
//	if err := srv.StartHTTP(); err != nil { // non-blocking, serves in a goroutine
//		return err
//	}
//	defer srv.StopHTTP()                  // graceful shutdown, closes services
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
