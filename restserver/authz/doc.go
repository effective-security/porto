// Package authz provides HTTP and gRPC authorization where URI paths (and
// their children) are allowed access by a set of roles. The caller supplies
// a way to map a request (or gRPC context) to an identity.Identity; the
// identity's Role() is checked against the configured path tree.
//
// Access control points are on entire URI segments only: Allow("/foo/bar",
// "bob") gives access to /foo/bar and /foo/bar/baz, but not /foo/barry.
//
// Access is based on the deepest matching path, not the accumulated paths:
//
//	Allow("/foo", "bob")
//	Allow("/foo/bar", "barry")
//
// allows barry access to /foo/bar but not to /foo, and bob to /foo but not
// to /foo/bar.
//
// AllowAny("/foo") allows any request (including guests) access to /foo.
// AllowAnyRole("/bar") allows any request with a non-empty, non-guest role
// access to /bar. AllowAny always overrides Allow/AllowAnyRole on the same
// node regardless of call order. Multiple calls to Allow for the same
// resource are cumulative.
//
// A Provider is usually built from a Config loaded from YAML/JSON:
//
//	allow:
//	  - /v1/admin:admin
//	  - /v1/items:admin,user
//	allow_any:
//	  - /v1/status
//	allow_any_role:
//	  - /v1/me
//	log_allowed: true
//	log_denied: true
//	log_level: DEBUG
//	logger_skip_paths:
//	  - path: /v1/status
//	    agent: kube-probe
//
//	p, err := authz.New(&cfg)
//	if err != nil {
//		return err
//	}
//	h, err := p.NewHandler(next)        // http.Handler; snapshots the tree
//	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(p.NewUnaryInterceptor()))
//
// Denied requests from unauthenticated callers (guest or empty role)
// receive a 401 httperror.Unauthorized response (codes.Unauthenticated for
// gRPC); denied requests from any other role receive a 403
// httperror.Forbidden response (codes.PermissionDenied). OPTIONS requests,
// including CORS preflights, are authorized like any other method: the
// preflight headers are caller-controlled, so a CORS middleware that answers
// preflights must run before the authz handler (restserver.NewMux and
// gserver place it there).
package authz
