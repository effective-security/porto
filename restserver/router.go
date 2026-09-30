package restserver

import (
	"net/http"

	"github.com/effective-security/porto/restserver/telemetry"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
)

// CORSOptions is a configuration container to setup the CORS middleware.
type CORSOptions struct {
	// AllowedOrigins is a list of origins a cross-domain request can be executed from.
	// If the special "*" value is present in the list, all origins will be allowed.
	// An origin may contain a wildcard (*) to replace 0 or more characters
	// (i.e.: http://*.domain.com). Usage of wildcards implies a small performance penalty.
	// Only one wildcard can be used per origin.
	// Default value is ["*"]
	AllowedOrigins []string
	// AllowOriginFunc is a custom function to validate the origin. It take the origin
	// as argument and returns true if allowed or false otherwise. If this option is
	// set, the content of AllowedOrigins is ignored.
	AllowOriginFunc func(origin string) bool
	// AllowOriginRequestFunc is a custom function to validate the origin. It takes the HTTP Request object and the
	// origin as argument and returns true if allowed or false otherwise. If this option is set, the content of
	// `AllowedOrigins` and `AllowOriginFunc` is ignored.
	AllowOriginRequestFunc func(r *http.Request, origin string) bool
	// AllowedMethods is a list of methods the client is allowed to use with
	// cross-domain requests. Default value is simple methods (HEAD, GET and POST).
	AllowedMethods []string
	// AllowedHeaders is list of non simple headers the client is allowed to use with
	// cross-domain requests.
	// If the special "*" value is present in the list, all headers will be allowed.
	// Default value is [] but "Origin" is always appended to the list.
	AllowedHeaders []string
	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS
	// API specification
	ExposedHeaders []string
	// MaxAge indicates how long (in seconds) the results of a preflight request
	// can be cached
	MaxAge int
	// AllowCredentials indicates whether the request can include user credentials like
	// cookies, HTTP authentication or client side SSL certificates.
	AllowCredentials bool
	// OptionsPassthrough instructs preflight to let other potential next handlers to
	// process the OPTIONS method. Turn this on if your application handles OPTIONS.
	OptionsPassthrough bool
	// Debugging flag adds additional output to debug server side CORS issues
	Debug bool
}

// Params is a Param-slice, as returned by the router.
// The slice is ordered, the first URL parameter is also the first slice value.
// It is therefore safe to read values by the index.
type Params httprouter.Params

// ByName returns the value of the first Param which key matches the given name.
// If no matching Param is found, an empty string is returned.
func (ps Params) ByName(name string) string {
	for i := range ps {
		if ps[i].Key == name {
			return ps[i].Value
		}
	}
	return ""
}

// Handle is a function that can be registered to a route to handle HTTP
// requests. Like http.HandlerFunc, but has a third parameter for the values of
// wildcards (variables).
type Handle func(http.ResponseWriter, *http.Request, Params)

// Router is the route registry handed to Service.Register. Paths use
// httprouter syntax (":name" and "*catchall" segments); registering the same
// method and path twice panics, as does registering after Handler has been
// served (httprouter is not safe for concurrent mutation). Before calling a
// handle, the Router records its registered path with telemetry.SetRoute,
// so request metrics are labelled by route template, not by URL path.
type Router interface {
	// Handler returns the http.Handler serving the registered routes,
	// wrapped with CORS when the router was created with NewRouterWithCORS.
	Handler() http.Handler
	// GET registers handle for GET requests to path.
	GET(path string, handle Handle)
	// HEAD registers handle for HEAD requests to path.
	HEAD(path string, handle Handle)
	// OPTIONS registers handle for OPTIONS requests to path.
	OPTIONS(path string, handle Handle)
	// POST registers handle for POST requests to path.
	POST(path string, handle Handle)
	// PUT registers handle for PUT requests to path.
	PUT(path string, handle Handle)
	// PATCH registers handle for PATCH requests to path.
	PATCH(path string, handle Handle)
	// DELETE registers handle for DELETE requests to path.
	DELETE(path string, handle Handle)
	// CONNECT registers handle for CONNECT requests to path.
	CONNECT(path string, handle Handle)
}

type proxy struct {
	router *httprouter.Router
	cors   *cors.Cors
}

// NewRouter returns a Router backed by httprouter with the given handler
// serving unmatched paths (restserver uses a JSON 404 not_found error).
func NewRouter(notfoundhandler http.HandlerFunc) Router {
	r := &proxy{
		router: httprouter.New(),
	}
	r.router.NotFound = notfoundhandler
	return r
}

// NewRouterWithCORS returns a Router whose Handler is wrapped by the rs/cors
// middleware configured from opt; a nil opt uses cors.Default() (all origins,
// simple methods, no credentials). Custom mux factories that also use
// restserver/authz must place the authz handler inside this Router's
// Handler, or wrap the authz handler with newCORS-equivalent middleware,
// so that preflights never bypass authorization; NewMux does the latter.
func NewRouterWithCORS(notfoundhandler http.HandlerFunc, opt *CORSOptions) Router {
	r := &proxy{
		router: httprouter.New(),
		cors:   newCORS(opt),
	}
	r.router.NotFound = notfoundhandler
	return r
}

// newCORS builds the rs/cors middleware from opt; a nil opt uses
// cors.Default(). Unless OptionsPassthrough is set, the middleware answers
// CORS preflights itself and never calls the wrapped handler for them.
func newCORS(opt *CORSOptions) *cors.Cors {
	if opt == nil {
		return cors.Default()
	}
	return cors.New(cors.Options{
		AllowedOrigins:             opt.AllowedOrigins,
		AllowOriginFunc:            opt.AllowOriginFunc,
		AllowOriginVaryRequestFunc: wrapAllowOriginRequestFunc(opt.AllowOriginRequestFunc),
		AllowedMethods:             opt.AllowedMethods,
		AllowedHeaders:             opt.AllowedHeaders,
		ExposedHeaders:             opt.ExposedHeaders,
		MaxAge:                     opt.MaxAge,
		AllowCredentials:           opt.AllowCredentials,
		OptionsPassthrough:         opt.OptionsPassthrough,
		Debug:                      opt.Debug,
	})
}

// proxyHandle adapts handle to httprouter and records path, the registered
// route template, for the request metrics.
func proxyHandle(path string, handle Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		telemetry.SetRoute(r.Context(), path)
		handle(w, r, Params(p))
	}
}

// Handler returns the router, wrapped with CORS when configured.
func (p *proxy) Handler() http.Handler {
	if p.cors != nil {
		return p.cors.Handler(p.router)
	}
	return p.router
}

// GET is a shortcut for router.Handle("GET", path, handle)
func (p *proxy) GET(path string, handle Handle) {
	p.router.Handle(http.MethodGet, path, proxyHandle(path, handle))
}

// HEAD is a shortcut for router.Handle("HEAD", path, handle)
func (p *proxy) HEAD(path string, handle Handle) {
	p.router.Handle(http.MethodHead, path, proxyHandle(path, handle))
}

// OPTIONS is a shortcut for router.Handle("OPTIONS", path, handle)
func (p *proxy) OPTIONS(path string, handle Handle) {
	p.router.Handle(http.MethodOptions, path, proxyHandle(path, handle))
}

// POST is a shortcut for router.Handle("POST", path, handle)
func (p *proxy) POST(path string, handle Handle) {
	p.router.Handle(http.MethodPost, path, proxyHandle(path, handle))
}

// PUT is a shortcut for router.Handle("PUT", path, handle)
func (p *proxy) PUT(path string, handle Handle) {
	p.router.Handle(http.MethodPut, path, proxyHandle(path, handle))
}

// PATCH is a shortcut for router.Handle("PATCH", path, handle)
func (p *proxy) PATCH(path string, handle Handle) {
	p.router.Handle(http.MethodPatch, path, proxyHandle(path, handle))
}

// DELETE is a shortcut for router.Handle("DELETE", path, handle)
func (p *proxy) DELETE(path string, handle Handle) {
	p.router.Handle(http.MethodDelete, path, proxyHandle(path, handle))
}

// CONNECT is a shortcut for router.Handle("CONNECT", path, handle)
func (p *proxy) CONNECT(path string, handle Handle) {
	p.router.Handle(http.MethodConnect, path, proxyHandle(path, handle))
}

// wrapAllowOriginRequestFunc adapts the CORSOptions.AllowOriginRequestFunc
// signature to the non-deprecated cors.Options.AllowOriginVaryRequestFunc.
// The returned function reports no extra Vary headers, which matches the
// behavior of the deprecated option it replaces. A nil input yields nil so the
// cors library falls back to AllowOriginFunc and AllowedOrigins.
func wrapAllowOriginRequestFunc(fn func(r *http.Request, origin string) bool) func(r *http.Request, origin string) (bool, []string) {
	if fn == nil {
		return nil
	}
	return func(r *http.Request, origin string) (bool, []string) {
		return fn(r, origin), nil
	}
}
