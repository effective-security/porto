package ready

import (
	"net/http"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/marshal"
)

var (
	errUnavailable = httperror.New(http.StatusServiceUnavailable, "not_ready", "the service is not ready yet")
)

// ServiceStatus is the readiness probe consulted on every request.
// restserver.Server satisfies it.
type ServiceStatus interface {
	// IsReady reports whether requests may be served right now. It is
	// called concurrently and must be cheap and safe for concurrent use.
	IsReady() bool
}

// ServiceReadyVerifier is a http.Handler that checks if the service is ready
// to serve, and if so chains to Delegate, otherwise calls NotReadyHandler.
// All fields must be set; NewServiceStatusVerifier provides the JSON 503
// default for NotReadyHandler.
type ServiceReadyVerifier struct {
	// Status is the readiness probe.
	Status ServiceStatus
	// Delegate handles requests while Status is ready.
	Delegate http.Handler
	// NotReadyHandler handles requests while Status is not ready.
	NotReadyHandler http.Handler
}

// ServeHTTP implements the http.Handler interface
func (c *ServiceReadyVerifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c.Status.IsReady() {
		c.Delegate.ServeHTTP(w, r)
	} else {
		c.NotReadyHandler.ServeHTTP(w, r)
	}
}

// NewServiceStatusVerifier returns a ServiceReadyVerifier that answers
// requests with a JSON 503 not_ready error (via marshal.WriteJSON) while s is
// not ready, and chains to delegate otherwise.
func NewServiceStatusVerifier(s ServiceStatus, delegate http.Handler) http.Handler {
	unavailable := func(w http.ResponseWriter, r *http.Request) {
		marshal.WriteJSON(w, r, errUnavailable)
	}
	v := ServiceReadyVerifier{
		Status:          s,
		Delegate:        delegate,
		NotReadyHandler: http.HandlerFunc(unavailable),
	}
	return &v
}
