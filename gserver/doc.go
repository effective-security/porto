// Package gserver implements a combined gRPC, gRPC-Web and REST server that
// listens on one or more URLs and multiplexes all three protocols on each
// listener.
//
// A Server is created with Start from a Config, a dig dependency container and
// a map of ServiceFactory functions. Each factory builds a Service; a Service
// that also implements RouteRegistrator gets its REST routes registered, and one
// that implements GRPCRegistrator gets its gRPC services registered. Plain
// HTTP/1.1 traffic is routed to the REST router, HTTP/2 "application/grpc"
// traffic to the gRPC server, and "application/grpc-web+proto" /
// "application/grpc-web-text" requests are translated to gRPC and their
// trailers are encoded into the gRPC-Web response body.
//
// Every request passes through a fixed middleware chain: rate limiting
// (optional), correlation ID, CORS (optional), identity extraction
// (roles.IdentityProvider built from Config.IdentityMap), metrics, request
// logging, authorization (restserver/authz built from Config.Authz), and a
// readiness check. gRPC calls go through the equivalent interceptor chain,
// prefixed by a panic-recovery interceptor and NewRequestValidationUnaryInterceptor.
//
// Minimal usage:
//
//	cfg := &gserver.Config{
//		ListenURLs: []string{"https://0.0.0.0:8443"},
//		Services:   []string{"status"},
//		ServerTLS: &gserver.TLSInfo{
//			CertFile: "server.pem",
//			KeyFile:  "server-key.pem",
//		},
//	}
//	factories := map[string]gserver.ServiceFactory{
//		"status": func(s gserver.GServer) any {
//			return func() error { s.AddService(newStatusService(s)); return nil }
//		},
//	}
//	srv, err := gserver.Start("api", cfg, container, factories)
//	if err != nil {
//		return err
//	}
//	defer srv.Close()
//	<-srv.Err() // or wait for a signal
//
// The container must provide discovery.Discovery and, when Config.IdentityMap
// enables JWT or DPoP authentication, a jwt.Parser. Config is typically loaded
// from YAML; see the yaml tags on Config for the field names.
package gserver
