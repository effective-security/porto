package rest

import (
	"net/http"

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
	// AllowOriginFunc is a custom function to validate the origin. It takes the HTTP Request object and the origin as
	// argument and returns true if allowed or false otherwise. If this option is set, the content of `AllowedOrigins`
	// and `AllowOriginFunc` is ignored.
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

// Router provides a router interface
type Router interface {
	Handler() http.Handler
	GET(path string, handle Handle)
	HEAD(path string, handle Handle)
	OPTIONS(path string, handle Handle)
	POST(path string, handle Handle)
	PUT(path string, handle Handle)
	PATCH(path string, handle Handle)
	DELETE(path string, handle Handle)
	CONNECT(path string, handle Handle)
}

type proxy struct {
	router *httprouter.Router
	cors   *cors.Cors
}

// NewRouter returns a new initialized Router.
func NewRouter(notfoundhandler http.HandlerFunc) Router {
	r := &proxy{
		router: httprouter.New(),
	}
	r.router.NotFound = notfoundhandler
	return r
}

// NewRouterWithCORS returns a new initialized Router with CORS enabled
func NewRouterWithCORS(notfoundhandler http.HandlerFunc, opt *CORSOptions) Router {
	var c *cors.Cors
	if opt != nil {
		c = cors.New(cors.Options{
			AllowedOrigins:         opt.AllowedOrigins,
			AllowOriginFunc:        opt.AllowOriginFunc,
			AllowOriginRequestFunc: opt.AllowOriginRequestFunc,
			AllowedMethods:         opt.AllowedMethods,
			AllowedHeaders:         opt.AllowedHeaders,
			ExposedHeaders:         opt.ExposedHeaders,
			MaxAge:                 opt.MaxAge,
			AllowCredentials:       opt.AllowCredentials,
			OptionsPassthrough:     opt.OptionsPassthrough,
			Debug:                  opt.Debug,
		})
	} else {
		c = cors.Default()
	}

	r := &proxy{
		router: httprouter.New(),
		cors:   c,
	}
	r.router.NotFound = notfoundhandler
	return r
}

func proxyHandle(handle Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		handle(w, r, Params(p))
	}
}

func (p *proxy) Handler() http.Handler {
	if p.cors != nil {
		return p.cors.Handler(p.router)
	}
	return p.router
}

// GET is a shortcut for router.Handle("GET", path, handle)
func (p *proxy) GET(path string, handle Handle) {
	p.router.Handle("GET", path, proxyHandle(handle))
}

// HEAD is a shortcut for router.Handle("HEAD", path, handle)
func (p *proxy) HEAD(path string, handle Handle) {
	p.router.Handle("HEAD", path, proxyHandle(handle))
}

// OPTIONS is a shortcut for router.Handle("OPTIONS", path, handle)
func (p *proxy) OPTIONS(path string, handle Handle) {
	p.router.Handle("OPTIONS", path, proxyHandle(handle))
}

// POST is a shortcut for router.Handle("POST", path, handle)
func (p *proxy) POST(path string, handle Handle) {
	p.router.Handle("POST", path, proxyHandle(handle))
}

// PUT is a shortcut for router.Handle("PUT", path, handle)
func (p *proxy) PUT(path string, handle Handle) {
	p.router.Handle("PUT", path, proxyHandle(handle))
}

// PATCH is a shortcut for router.Handle("PATCH", path, handle)
func (p *proxy) PATCH(path string, handle Handle) {
	p.router.Handle("PATCH", path, proxyHandle(handle))
}

// DELETE is a shortcut for router.Handle("DELETE", path, handle)
func (p *proxy) DELETE(path string, handle Handle) {
	p.router.Handle("DELETE", path, proxyHandle(handle))
}

// CONNECT is a shortcut for router.Handle("CONNECT", path, handle)
func (p *proxy) CONNECT(path string, handle Handle) {
	p.router.Handle("CONNECT", path, proxyHandle(handle))
}
