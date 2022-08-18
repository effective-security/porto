package authz

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/correlation"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/porto/xhttp/identity"
	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"
)

var ctx = identity.AddToContext(context.Background(), identity.NewRequestContext(nil))

func Test_NewConfig(t *testing.T) {
	_, err := New(&Config{Allow: []string{"/a"}})
	assert.Error(t, err, "Should fail without :")

	_, err = New(&Config{Allow: []string{"/a:"}})
	assert.Error(t, err, "Should fail without service")

	_, err = New(&Config{Allow: []string{"/a:,"}})
	assert.NoError(t, err, "Empty service will not be mapped")
}

func TestPathNode_New(t *testing.T) {
	n := newPathNode("bob")
	assert.Equal(t, "bob", n.value, "node.value should be 'bob'")

	assert.NotNil(t, n.children, "node.children shouldn't be nil")
	assert.Equal(t, 0, len(n.children), "node.children should be initialized to an empty map")

	assert.NotNil(t, n.allowedRoles, "node.allowedRoles shouldn't be nil")
	assert.Equal(t, 0, len(n.allowedRoles), "node.allowedRoles should be initialized to an empty map")
	assert.Equal(t, allowTypes(0), n.allow, "node.allow should be initialized to 0")
}

func TestPathNode_CloneNil(t *testing.T) {
	var n *pathNode
	c := n.clone()
	assert.Nil(t, c, "pathNode.clone() for a nil pathNode should return nil")
}

func TestPathNode_Clone(t *testing.T) {
	n := newPathNode("bob")
	n.children["foo"] = newPathNode("foo")
	n.children["quz"] = newPathNode("quz")
	n.allowedRoles["barry"] = true
	n.allow = allowAnyRole

	c := n.clone()
	assertPathNodesEqual(t, []string{}, c, n)
}

func assertPathNodesEqual(t *testing.T, path []string, a, b *pathNode) {
	assert.Equal(t, a.value, b.value, "[%v] pathNode.Value's don't match", path)
	assert.Equal(t, a.allow, b.allow, "[%v] pathNode.allow don't match", path)
	assert.Equal(t, a.allowedRoles, b.allowedRoles, "[%v] pathNode.allowedRoles don't match", path)
	assert.Equal(t, len(a.children), len(b.children), "[%v] children different lengths", path)

	for c, cn := range a.children {
		bc, exists := b.children[c]
		if assert.True(t, exists, "[%v] child %v missing ", path, c) {
			if bc == cn {
				assert.Fail(t, "[%v] child %v has same child instance", path, c)
			} else {
				assertPathNodesEqual(t, append(path, a.value), cn, bc)
			}
		}
	}
	for c := range b.children {
		_, exists := a.children[c]
		assert.True(t, exists, "[%v] child %v missing", path, c)
	}
}

func TestConfig_WalkTree(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)
	n1 := c.walkPath("/foo/bar", true)
	n2 := c.walkPath("/foo/bar/baz", true)
	n3 := c.walkPath("/foo/bar/bam", true)
	n4 := c.walkPath("/baz", true)
	// resulting tree should be
	// rootPath
	//    - baz
	//    - foo
	//        - bar
	//            -baz
	//            -bam
	assert.Equal(t, []string{"baz", "foo"}, childNames(c.pathRoot.children), "Root pathNode should have these children")
	assert.Equal(t, 0, len(c.pathRoot.children["baz"].children), "/baz should have no children")
	assert.Equal(t, n4, c.pathRoot.children["baz"], "node returned for /baz is different to the node returned by manually walking the tree!")

	foo := c.pathRoot.children["foo"]
	assert.Equal(t, "foo", foo.value, "node for /foo should have value 'foo'")

	bar := foo.children["bar"]
	assert.NotNil(t, bar, "node for /foo should have a child 'bar', but it doesn't exist")
	assert.Equal(t, n1, bar, "walkPath(/foo/bar) returned different node to resulting tree")

	assert.Equal(t, []string{"bam", "baz"}, childNames(bar.children),
		"/foo/bar node should have children bam, baz")

	assert.Equal(t, n2, bar.children["baz"], "/foo/bar/baz returned different node to the on in the tree")
	assert.Equal(t, n3, bar.children["bam"], "/foo/bar/bam returned different node to the one in the tree")
	assert.Equal(t, n1, c.walkPath("/foo/bar", false), "walkPath for existing path returned different node")
	assert.Equal(t, n3, c.walkPath("/foo/bar/bam", false), "walkPath for existing path returned different node")

	// should get the deepest node that exists
	alice := c.walkPath("/foo/bar/alice", false)
	assert.Equal(t, n1, alice, "walkPath(/foo/bar/alice) shoud return node for /foo/bar")
}

func checkAllowed(t *testing.T, c *Provider, path string, idn identity.Identity, expectedAllowed bool) {
	actual := c.isAllowed(ctx, path, idn)
	assert.Equal(t, expectedAllowed, actual, "isAllowed(%v, %v) returned unexpected results", path, idn.String())
}

func TestConfigYaml(t *testing.T) {
	yml := `---
allow_any:
  - /favicon.ico
  - /v1
allow_any_role:
allow:
log_allowed_any: false
log_allowed: true
log_denied: true
`
	var cfg Config
	err := yaml.Unmarshal([]byte(yml), &cfg)
	require.NoError(t, err)

	assert.True(t, cfg.LogAllowed)
	assert.True(t, cfg.LogDenied)
}

func TestConfig_Allow(t *testing.T) {
	c, err := New(&Config{
		Allow: []string{
			"/foo:bob",
			"/foo/bar:bob,alice",
			"/baz/baz:bob,baz",
		},
	})
	require.NoError(t, err)
	t.Log(c.treeAsText())

	check := func(path, role string, allowed bool) {
		idn := identity.NewIdentity(role, "test", nil)
		checkAllowed(t, c, path, idn, allowed)
	}
	check("/foo", "bob", true)
	check("/foo", "alice", false)
	check("/foo", "", false)
	check("/foo/more", "bob", true)
	check("/foo/more", "alice", false)
	check("/foo/bar", "bob", true)
	check("/foo/bar", "alice", true)
	check("/foo/bar", "baz", false)
	check("/foo/bar/bananas", "bob", true)
	check("/foo/bar/bananas", "alice", true)
	check("/foo/bar/bananas", "baz", false)
	check("/who", "bob", false)
	check("/", "bob", false)
	check("/baz", "bob", false)
	check("/baz/baz", "bob", true)
	check("/baz/baz", "baz", true)
	check("/baz/baz", "alice", false)
	c, err = New(&Config{
		Allow: []string{
			"/:bob",
			"/alice:alice",
		},
	})
	require.NoError(t, err)
	check("/", "bob", true)
	check("/", "alice", false)
	check("/who", "bob", true)
	check("/who", "alice", false)
	check("/alice", "bob", false)
	check("/alice", "alice", true)
}

func TestConfig_AllowAny(t *testing.T) {
	c, err := New(&Config{
		Allow: []string{
			"/foo/alice:alice",
		},
		AllowAny: []string{
			"/foo",
			"/bar",
		},
		AllowAnyRole: []string{
			"/foo/eve",
		},
	})
	require.NoError(t, err)
	check := func(path, role string, allowed bool) {
		idn := identity.NewIdentity(role, "test", nil)
		checkAllowed(t, c, path, idn, allowed)
	}
	check("/", "alice", false)
	check("/", "bob", false)
	check("/", "", false)
	check("/foo", "alice", true)
	check("/foo", "bob", true)
	check("/foo", "", true)
	check("/foo/q", "alice", true)
	check("/foo/q", "bob", true)
	check("/foo/q", "", true)
	check("/bar", "alice", true)
	check("/random", "alice", false)
	check("/foo/alice", "alice", true)
	check("/foo/alice", "bob", false)
	check("/foo/eve", "", false)
	check("/foo/eve", "bob", true)
	check("/foo/eve", "alice", true)
	check("/foo/eve", "eve", true)
	check("/foo/eve", "barry", true)
}

func TestConfig_TreeAsText(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)
	c.AllowAny("/")
	c.Allow("/foo/alice", "svc_alice", "svc_bob")
	c.Allow("/foo/eve", "svc_eve", "svc_alice")
	c.Allow("/bar", "svc_bob")
	c.AllowAnyRole("/eve/public")
	exp := "\n" +
		"  /                                [Any]\n" +
		"    bar                            [svc_bob]\n" +
		"    eve/                           \n" +
		"      public                       [Any Role]\n" +
		"    foo/                           \n" +
		"      alice                        [svc_alice,svc_bob]\n" +
		"      eve                          [svc_alice,svc_eve]\n"

	assert.Equal(t, exp, c.treeAsText())
}

func Test_AccessLogs(t *testing.T) {
	xlog.TimeNowFn = func() time.Time {
		date, _ := time.Parse("2006-01-02", "2021-04-01")
		return date
	}

	c, err := New(&Config{LogAllowed: true, LogDenied: true, LogAllowedAny: true})
	require.NoError(t, err)
	c.AllowAny("/")
	c.Allow("/foo/alice", "svc_alice", "svc_bob")
	c.Allow("/foo/eve", "svc_eve", "svc_alice")
	c.Allow("/bar", "svc_bob")
	c.AllowAnyRole("/eve/public")

	// check logging on isAllowed calls
	buf := bytes.NewBuffer([]byte{})
	xlog.SetFormatter(xlog.NewStringFormatter(buf))

	cid1 := correlation.ID(ctx)
	cid2 := correlation.ID(ctx)
	assert.Equal(t, cid1, cid2)

	shouldLog := func(path, service, expLog string) {
		buf.Reset()
		c.isAllowed(ctx, path, identity.NewIdentity(service, "test", nil))
		result := buf.String()
		assert.Equal(t, expLog, result, "Unexpected log output for isAllowed(%q, %q)", path, service)
	}

	t.Run("logs", func(t *testing.T) {
		buf.Reset()
		shouldLog("/", "bobby", "time=2021-04-01T00:00:00Z level=N pkg=authz func=isAllowed status=\"allowed_any\" role=\"bobby\" user=\"test\" email=\"\" path=\"/\" node=\"\" ctx=\"\"\n")
		shouldLog("/bob", "svc_bob", "time=2021-04-01T00:00:00Z level=N pkg=authz func=isAllowed status=\"allowed_any\" role=\"svc_bob\" user=\"test\" email=\"\" path=\"/bob\" node=\"\" ctx=\"\"\n")
		shouldLog("/bar", "svc_bob", "time=2021-04-01T00:00:00Z level=N pkg=authz func=isAllowed status=\"allowed\" role=\"svc_bob\" user=\"test\" email=\"\" path=\"/bar\" node=\"bar\" ctx=\"\"\n")
		shouldLog("/bar", "svc_eve", "time=2021-04-01T00:00:00Z level=N pkg=authz func=isAllowed status=\"denied\" role=\"svc_eve\" user=\"test\" email=\"\" path=\"/bar\" node=\"bar\" ctx=\"\"\n")
		shouldLog("/foo/eve", "svc_eve", "time=2021-04-01T00:00:00Z level=N pkg=authz func=isAllowed status=\"allowed\" role=\"svc_eve\" user=\"test\" email=\"\" path=\"/foo/eve\" node=\"eve\" ctx=\"\"\n")
		shouldLog("/foo/eve", "svc_bob", "time=2021-04-01T00:00:00Z level=N pkg=authz func=isAllowed status=\"denied\" role=\"svc_bob\" user=\"test\" email=\"\" path=\"/foo/eve\" node=\"eve\" ctx=\"\"\n")
	})

	t.Run("nologs", func(t *testing.T) {
		c.cfg.LogAllowedAny = false
		c.cfg.LogAllowed = false
		c.cfg.LogDenied = false
		buf.Reset()
		c.isAllowed(ctx, "/", identity.NewIdentity("bobby", "test", nil))
		c.isAllowed(ctx, "/bob", identity.NewIdentity("svc_bob", "test", nil))
		c.isAllowed(ctx, "/bar", identity.NewIdentity("svc_bob", "test", nil))
		c.isAllowed(ctx, "/bar", identity.NewIdentity("svc_eve", "test", nil))
		c.isAllowed(ctx, "/foo/eve", identity.NewIdentity("svc_eve", "test", nil))
		c.isAllowed(ctx, "/foo/eve", identity.NewIdentity("svc_bob", "test", nil))
		assert.Empty(t, buf.Bytes())
	})
}

func TestConfig_InvalidPath(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)
	defer func() {
		e := recover()
		assert.Equal(t, "Invalid path supplied to walkPath bob", e)
	}()
	c.Allow("bob", "bob")
}

func TestConfig_Clone(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	c.SetGRPCRoleMapper(gRPCRoleMapper("bob"))
	c.SetRoleMapper(roleMapper("bob"))
	c.Allow("/", "bob")
	clone := c.Clone()
	c.Allow("/foo", "alice")
	require.NotNil(t, clone.requestRoleMapper, "Config.Clone() didn't clone roleMapper")
	assert.Equal(t, "bob", clone.requestRoleMapper(nil).Role(), "Config.Clone() has a roleMapper set, but it doesn't appear to be ours!")
	assert.False(t, clone.isAllowed(ctx, "/foo", identity.NewIdentity("alise", "test", nil)), "Config.Clone() returns a clone that was mutated by mutating the original instance (should be a deep copy)")
	assert.True(t, clone.isAllowed(ctx, "/foo", identity.NewIdentity("bob", "test", nil)), "Config.Clone() return a clone that's missing an Allow() from the source")
}

func TestConfig_checkAccess_defaultMapper(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	c.Allow("/foo", "bob")
	r, _ := http.NewRequest(http.MethodGet, "/foo", nil)
	assert.EqualError(t, c.checkAccess(r), "guest role not allowed")

	r, _ = http.NewRequest(http.MethodGet, "*", nil)
	assert.EqualError(t, c.checkAccess(r), "guest role not allowed")
}

func TestConfig_checkAccess_noTLS(t *testing.T) {
	c, err := New(&Config{})
	require.NoError(t, err)

	c.Allow("/foo", "bob")
	c.SetRoleMapper(roleMapper("bob"))
	r, _ := http.NewRequest(http.MethodGet, "/foo", nil)
	assert.NoError(t, c.checkAccess(r), "bob should be allowed access to /foo, but wasn't")

	r, _ = http.NewRequest(http.MethodGet, "/", nil)
	assert.Error(t, c.checkAccess(r), "bob shouldn't be allowed access to / but was")

	r, _ = http.NewRequest(http.MethodOptions, "/", nil)
	assert.NoError(t, c.checkAccess(r), "OPTIONS should be allowed")
}

func TestConfig_HandlerNotValid(t *testing.T) {
	delegate := http.HandlerFunc(testHTTPHandler)
	c, err := New(&Config{})
	require.NoError(t, err)

	c.SetRoleMapper(roleMapper("bob"))
	_, err = c.NewHandler(delegate)
	assert.Equal(t, ErrNoPathsConfigured, errors.Cause(err), "Got wrong error when trying to create a Handler with no allowed paths")

	c.AllowAny("/")
	h, err := c.NewHandler(delegate)
	assert.NoError(t, err)
	assert.NotNil(t, h)

	c.SetRoleMapper(nil)
	_, err = c.NewHandler(delegate)
	assert.Equal(t, ErrNoRoleMapperSpecified, errors.Cause(err), "Got wrong error when trying to create a Handler with no RoleMapper configured")
}

func TestConfig_Handler(t *testing.T) {
	delegate := http.HandlerFunc(testHTTPHandler)
	c, err := New(&Config{})
	require.NoError(t, err)

	c.SetRoleMapper(roleMapper("bob"))
	c.AllowAny("/who")
	c.Allow("/bob", "bob")
	c.Allow("/alice", "alice")
	h, err := c.NewHandler(delegate)
	assert.NoError(t, err, "Unexpected error creating http.Handler")

	testHandler := func(path string, allowed bool) {
		r, err := http.NewRequest(http.MethodGet, path, nil)
		assert.NoError(t, err, "Unable to create http.Request")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if allowed {
			assert.Equal(t, http.StatusOK, w.Code, "Request to %v should be allowed but got HTTP StatusCode %d", path, w.Code)
		} else {
			assert.Equal(t, http.StatusUnauthorized, w.Code, "Request to %v shouldn't be authorized", path)

			ct := w.HeaderMap.Get("Content-Type")
			assert.Equal(t, header.ApplicationJSON, ct, "Unauthorized response should have an application/json contentType")

			body := w.Body.String()
			assert.JSONEq(t, `{"code":"unauthorized", "message":"bob/test role not allowed"}`, body)
		}
	}
	testHandler("/who", true)
	testHandler("/who?pp", true)
	testHandler("/bob", true)
	testHandler("/bob/some/more", true)
	testHandler("/alice", false)
	testHandler("/alice/more", false)
	testHandler("/somewhereElse", false)
	testHandler("/", false)
}

func TestNewUnaryInterceptor(t *testing.T) {
	c, err := New(&Config{
		AllowAny: []string{
			"/pb.Service/method1",
		},
		Allow: []string{
			"/pb.Service/method2:bob",
		},
	})
	require.NoError(t, err)

	unary := c.NewUnaryInterceptor()
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	}

	si := &grpc.UnaryServerInfo{
		FullMethod: "/pb.Service/method1",
	}
	_, err = unary(context.Background(), nil, si, handler)
	require.NoError(t, err)

	si = &grpc.UnaryServerInfo{
		FullMethod: "/pb.Service/method2",
	}
	_, err = unary(context.Background(), nil, si, handler)
	require.Error(t, err)
	assert.Equal(t, `rpc error: code = PermissionDenied desc = guest role not allowed`, err.Error())
}

func testHTTPHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello"))
}

func roleMapper(role string) func(*http.Request) identity.Identity {
	return func(*http.Request) identity.Identity {
		return identity.NewIdentity(role, "test", nil)
	}
}

func gRPCRoleMapper(role string) func(ctx context.Context) identity.Identity {
	return func(ctx context.Context) identity.Identity {
		return identity.NewIdentity(role, "test", nil)
	}
}

func childNames(m map[string]*pathNode) []string {
	r := make([]string, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
