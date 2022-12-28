// Package authz provides an implemention of http authorization where specific
// URI (or URI's and their children) are allowed access by a set of roles
//
// the caller can supply a way to map from a request to a role name.
//
// the access control points are on entire URI segments only, e.g.
// Allow("/foo/bar", "bob")
// gives access to /foo/bar /foo/bar/baz, but not /foo/barry
//
// Access is based on the deepest matching path, not the accumulated paths, so,
// Allow("/foo", "bob")
// Allow("/foo/bar", "barry")
// will allow barry access to /foo/bar but not access to /foo
//
// AllowAny("/foo") will allow any authenticated request access to the /foo resource
// AllowAnyRole("/bar") will allow any authenticated request with a non-empty role access to the /bar resource
//
// AllowAny, allowAnyRole always overrides any matching Allow regardless of the order of calls
// multiple calls to Allow for the same resource are cumulative, e.g.
// Allow("/foo", "bob")
// Allow("/foo", "barry")
// is equivilent to
// Allow("/foo", "bob", "barry")
//
// Once you've built your Provider you can call NewHandler to get a http.Handler
// that implements those rules.
package authz

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/effective-security/porto/x/math"
	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/porto/xhttp/marshal"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/restserver", "authz")

var (
	// ErrNoRoleMapperSpecified can't call NewHandler before you've set the RoleMapper function
	ErrNoRoleMapperSpecified = errors.New("you must have a RoleMapper set to be able to create a http.Handler")
	// ErrNoPathsConfigured is returned by NewHandler if you call NewHandler, but haven't configured any paths to be accessible
	ErrNoPathsConfigured = errors.New("you must have at least one path before being able to create a http.Handler")
)

// HTTPAuthz represents an Authorization provider interface,
// You can call Allow or AllowAny to specify which roles are allowed
// access to which path segments.
// once configured you can create a http.Handler that enforces that
// configuration for you by calling NewHandler
type HTTPAuthz interface {
	// SetRoleMapper configures the function that provides the mapping from an HTTP request to a role name
	SetRoleMapper(func(*http.Request) identity.Identity)
	// NewHandler returns a http.Handler that enforces the current authorization configuration
	// The handler has its own copy of the configuration changes to the Provider after calling
	// NewHandler won't affect previously created Handlers.
	// The returned handler will extract the role and verify that the role has access to the
	// URI being request, and either return an error, or pass the request on to the supplied
	// delegate handler
	NewHandler(delegate http.Handler) (http.Handler, error)
}

// GRPCAuthz represents an Authorization provider interface,
// You can call Allow or AllowAny to specify which roles are allowed
// access to which path segments.
// once configured you can create a Unary interceptor that enforces that
// configuration for you by calling NewUnaryInterceptor
type GRPCAuthz interface {
	// SetGRPCRoleMapper configures the function that provides
	// the mapping from a gRPC request to a role name
	SetGRPCRoleMapper(m func(ctx context.Context) identity.Identity)
	// NewUnaryInterceptor returns grpc.UnaryServerInterceptor that enforces the current
	// authorization configuration.
	// The returned interceptor will extract the role and verify that the role has access to the
	// URI being request, and either return an error, or pass the request on to the supplied
	// delegate handler
	NewUnaryInterceptor() grpc.UnaryServerInterceptor
}

// Config contains configuration for the authorization module
type Config struct {
	// Allow will allow the specified roles access to this path and its children, in format: ${path}:${role},${role}
	Allow []string `json:"allow" yaml:"allow"`

	// AllowAny will allow any authenticated request access to this path and its children
	AllowAny []string `json:"allow_any" yaml:"allow_any"`

	// AllowAnyRole will allow any authenticated request that include a non empty role
	AllowAnyRole []string `json:"allow_any_role" yaml:"allow_any_role"`

	// LogAllowedAny specifies to log allowed access to nodes in AllowAny list
	LogAllowedAny bool `json:"log_allowed_any" yaml:"log_allowed_any"`

	// LogAllowed specifies to log allowed access
	LogAllowed bool `json:"log_allowed" yaml:"log_allowed"`

	// LogDenied specifies to log denied access
	LogDenied bool `json:"log_denied" yaml:"log_denied"`
}

// Provider represents an Authorization provider,
// You can call Allow or AllowAny to specify which roles are allowed
// access to which path segments.
// once configured you can create a http.Handler that enforces that
// configuration for you by calling NewHandler
type Provider struct {
	requestRoleMapper func(*http.Request) identity.Identity
	grpcRoleMapper    func(context.Context) identity.Identity
	pathRoot          *pathNode
	cfg               *Config
}

type allowTypes int8

const (
	allowAny allowTypes = 1 << iota
	allowAnyRole
)

// the auth info is stored in a tree based on the path segments
// the deepest node that matches the request is used to validate the request
// e.g. if /v1/foo is allowed access by sales and
//
//	/v1/bar is allowed access by baristas
//
// the tree is
// ""
//   - "v1"
//   - "foo"	allow sales
//   - "bar" allow baristas
type pathNode struct {
	value        string
	children     map[string]*pathNode
	allowedRoles map[string]bool
	allow        allowTypes
}

var defaultRoleMapper = func(r *http.Request) identity.Identity {
	return identity.FromRequest(r).Identity()
}

var defaultGrpcRoleMapper = func(ctx context.Context) identity.Identity {
	return identity.FromContext(ctx).Identity()
}

// New returns new Authz provider
func New(cfg *Config) (*Provider, error) {
	az := &Provider{
		cfg:               cfg,
		requestRoleMapper: defaultRoleMapper,
		grpcRoleMapper:    defaultGrpcRoleMapper,
	}

	for _, s := range cfg.AllowAny {
		az.AllowAny(s)
		logger.KV(xlog.NOTICE, "AllowAny", s)
	}

	for _, s := range cfg.AllowAnyRole {
		az.AllowAnyRole(s)
		logger.KV(xlog.NOTICE, "AllowAnyRole", s)
	}

	for _, s := range cfg.Allow {
		parts := strings.Split(s, ":")
		if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
			return nil, errors.Errorf("not valid Authz allow configuration: %q", s)
		}
		logger.KV(xlog.NOTICE, "allow", parts[0], "role", parts[1])
		roles := strings.Split(parts[1], ",")
		az.Allow(parts[0], roles...)
	}

	return az, nil
}

// treeAtText will return a string of the current configured tree in
// human readable text format.
func (c *Provider) treeAsText() string {
	o := bytes.NewBuffer(make([]byte, 0, 256))
	_, _ = io.WriteString(o, "\n")
	roles := func(o io.Writer, n *pathNode) {
		if n.allowAny() {
			_, _ = io.WriteString(o, "[Any]")
			return
		}
		if (n.allow & allowAnyRole) != 0 {
			_, _ = io.WriteString(o, "[Any Role]")
			return
		}
		if len(n.allowedRoles) == 0 {
			return
		}
		fmt.Fprintf(o, "[%s]", strings.Join(n.allowedRoleKeys(), ","))
	}
	var visitNode func(int, *pathNode)
	visitNode = func(depth int, n *pathNode) {
		pad := strings.Repeat(" ", depth*2)
		slash := ""
		if len(n.children) > 0 {
			slash = "/"
		}
		rolePad := strings.Repeat(" ", math.Max(1, 32-len(pad)-len(slash)-len(n.value)))
		fmt.Fprintf(o, "%s  %s%s %s", pad, n.value, slash, rolePad)
		roles(o, n)
		fmt.Fprintln(o)
		for _, ck := range n.childKeys() {
			visitNode(depth+1, n.children[ck])
		}
	}
	visitNode(0, c.pathRoot)
	return o.String()
}

// newPathNode returns a newly created pathNode initialized with the supplied path segment
func newPathNode(pathItem string) *pathNode {
	return &pathNode{
		value:        pathItem,
		children:     make(map[string]*pathNode),
		allowedRoles: make(map[string]bool),
	}
}

// childKeys returns a slice containing the child key names sorted alpabetically
func (n *pathNode) childKeys() []string {
	r := make([]string, 0, len(n.children))
	for k := range n.children {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

// allowedRoleKeys return a slice containing the allowed role name sorted alphabetically
func (n *pathNode) allowedRoleKeys() []string {
	r := make([]string, 0, len(n.allowedRoles))
	for k := range n.allowedRoles {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

// clone returns a deep copy of this pathNode
func (n *pathNode) clone() *pathNode {
	if n == nil {
		return nil
	}
	c := newPathNode(n.value)
	c.allow = n.allow
	for k, v := range n.children {
		c.children[k] = v.clone()
	}
	for k := range n.allowedRoles {
		c.allowedRoles[k] = true
	}
	return c
}

func (n *pathNode) allowAny() bool {
	return (n.allow & allowAny) != 0
}

func (n *pathNode) allowRole(r string) bool {
	if r == "" || r == identity.GuestRoleName {
		return false
	}
	return ((n.allow & allowAnyRole) != 0) || n.allowedRoles[r]
}

// Clone returns a deep copy of this Provider
func (c *Provider) Clone() *Provider {
	p := &Provider{
		requestRoleMapper: c.requestRoleMapper,
		grpcRoleMapper:    c.grpcRoleMapper,
		pathRoot:          c.pathRoot.clone(),
		cfg:               &Config{},
	}

	_ = copier.Copy(p.cfg, c.cfg)

	return p
}

// SetRoleMapper configures the function that provides the mapping from an HTTP request to a role name
func (c *Provider) SetRoleMapper(m func(r *http.Request) identity.Identity) {
	c.requestRoleMapper = m
}

// SetGRPCRoleMapper configures the function that provides the mapping from a gRPC request to a role name
func (c *Provider) SetGRPCRoleMapper(m func(ctx context.Context) identity.Identity) {
	c.grpcRoleMapper = m
}

// AllowAny will allow any authenticated request access to this path and its children
// [unless a specific Allow/AllowAny is called for a child path]
func (c *Provider) AllowAny(path string) {
	c.walkPath(path, true).allow = allowAny
}

// AllowAnyRole will allow any authenticated request that include a non empty role
// access to this path and its children
// [unless a specific Allow/AllowAny is called for a child path]
func (c *Provider) AllowAnyRole(path string) {
	c.walkPath(path, true).allow |= allowAnyRole
}

// Allow will allow the specified roles access to this path and its children
// [unless a specific Allow/AllowAny is called for a child path]
// multiple calls to Allow for the same path are cumulative
func (c *Provider) Allow(path string, roles ...string) {
	node := c.walkPath(path, true)
	for _, role := range roles {
		if role == "" {
			continue
		}
		node.allowedRoles[role] = true
	}
}

// walkPath does the work of converting a URI path into a tree of pathNodes
// if create is true, all nodes required to create a tree equaling the supplied
// path will be created if needed.
// if create is false, the deepest node matching the supplied path is returned.
//
// walkPath is safe for concurrent use only if create is false, and it has previously
// been called with create=true
func (c *Provider) walkPath(path string, create bool) *pathNode {
	if len(path) == 0 || path[0] != '/' {
		panic(fmt.Sprintf("Invalid path supplied to walkPath %v", path))
	}
	if c.pathRoot == nil {
		c.pathRoot = newPathNode("")
	}
	pathLen := len(path)
	pathPos := 1
	currentNode := c.pathRoot
	for pathPos < pathLen {
		segEnd := pathPos
		for segEnd < pathLen && path[segEnd] != '/' {
			segEnd++
		}
		pathSegment := path[pathPos:segEnd]
		childNode := currentNode.children[pathSegment]
		if childNode == nil && !create {
			return currentNode
		}
		if childNode == nil {
			childNode = newPathNode(pathSegment)
			currentNode.children[pathSegment] = childNode
		}
		currentNode = childNode
		pathPos = segEnd + 1
	}
	return currentNode
}

// isAllowed returns true if access to 'path' is allowed for the specified role.
func (c *Provider) isAllowed(ctx context.Context, path string, idn identity.Identity) bool {
	cid := correlation.ID(ctx)
	role := idn.Role()
	subj := idn.Subject()
	claims := jwt.MapClaims(idn.Claims())
	email := claims.String("email")

	if len(path) == 0 || path[0] != '/' {
		logger.KV(xlog.NOTICE, "status", "denied",
			"invalid_path", path,
			"role", role,
			"user", subj,
			"email", email,
			"ctx", cid)
		return false
	}

	node := c.walkPath(path, false)
	allowAny := node.allowAny()
	allowRole := false

	if !allowAny {
		allowRole = node.allowRole(role)
	}
	res := allowAny || allowRole
	if res {
		if allowRole && c.cfg.LogAllowed {
			logger.KV(xlog.NOTICE, "status", "allowed",
				"role", role,
				"user", subj,
				"email", email,
				"path", path,
				"node", node.value,
				"ctx", cid)
		} else if c.cfg.LogAllowedAny {
			logger.KV(xlog.NOTICE, "status", "allowed_any",
				"role", role,
				"user", subj,
				"email", email,
				"path", path,
				"node", node.value,
				"ctx", cid)
		}
	} else if c.cfg.LogDenied {
		logger.KV(xlog.NOTICE, "status", "denied",
			"role", role,
			"user", subj,
			"email", email,
			"path", path,
			"node", node.value,
			"ctx", cid)
	}
	return res
}

// checkAccess ensures that access to the supplied http.request is allowed
func (c *Provider) checkAccess(r *http.Request) error {
	if r.Method == http.MethodOptions {
		// always allow OPTIONS
		return nil
	}

	idn := c.requestRoleMapper(r)
	if !c.isAllowed(r.Context(), r.URL.Path, idn) {
		return errors.Errorf("%s role not allowed", idn.String())
	}

	return nil
}

// NewHandler returns a http.Handler that enforces the current authorization configuration
// The handler has its own copy of the configuration changes to the Provider after calling
// NewHandler won't affect previously created Handlers.
// The returned handler will extract the role and verify that the role has access to the
// URI being request, and either return an error, or pass the request on to the supplied
// delegate handler
func (c *Provider) NewHandler(delegate http.Handler) (http.Handler, error) {
	if c.requestRoleMapper == nil {
		return nil, errors.WithStack(ErrNoRoleMapperSpecified)
	}
	if c.pathRoot == nil {
		return nil, errors.WithStack(ErrNoPathsConfigured)
	}
	h := &authHandler{
		delegate: delegate,
		config:   c.Clone(),
	}
	logger.KV(xlog.INFO, "config", h.config.treeAsText())
	return h, nil
}

type authHandler struct {
	delegate http.Handler
	config   *Provider
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := a.config.checkAccess(r)
	if err == nil {
		a.delegate.ServeHTTP(w, r)
	} else {
		marshal.WriteJSON(w, r, httperror.Unauthorized(err.Error()))
	}
}

// NewUnaryInterceptor returns grpc.UnaryServerInterceptor to check access
func (c *Provider) NewUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		idn := c.grpcRoleMapper(ctx)
		if !c.isAllowed(ctx, info.FullMethod, idn) {
			return nil, status.Errorf(codes.PermissionDenied, "%s role not allowed", idn.String())
		}

		return handler(ctx, req)
	}
}
