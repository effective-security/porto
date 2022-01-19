package rest

// Service provides a way for subservices to be registered so they get added to the http API.
type Service interface {
	Name() string
	Register(Router)
	Close()
	// IsReady indicates that service is ready to serve its end-points
	IsReady() bool
}
