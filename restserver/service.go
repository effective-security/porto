package restserver

// Service is a component that contributes routes to the HTTPServer. It is
// registered with HTTPServer.AddService and its lifecycle is driven by the
// server: Register during StartHTTP (mux creation), Close during StopHTTP.
type Service interface {
	// Name returns the unique service name used for registration and lookup.
	Name() string
	// Register adds the service's routes to the router.
	Register(Router)
	// Close releases the service's resources after StopHTTP drains requests.
	// It is called once, even when the shutdown deadline expires.
	Close()
	// IsReady indicates that service is ready to serve its end-points;
	// while any service returns false the server answers 503 to all requests.
	IsReady() bool
}
