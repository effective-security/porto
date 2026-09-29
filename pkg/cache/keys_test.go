package cache

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNamespace(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		prefix  string
		key     string
		name    string
		rel     string
		pattern string
		glob    string
	}{
		{prefix: "root", key: "x", name: "root/x", rel: "x", pattern: "*", glob: "root/*"},
		{prefix: "root", key: "/x/", name: "root/x", rel: "x", pattern: "/x*/", glob: "root/x*"},
		{prefix: "root", key: "a//b", name: "root/a/b", rel: "a/b", pattern: "a//*", glob: "root/a/*"},
		// ".." cannot leave the prefix, in keys and patterns (formerly P-044)
		{prefix: "root", key: "../x", name: "root/x", rel: "x", pattern: "../*", glob: "root/*"},
		{prefix: "root", key: "a/../../b", name: "root/b", rel: "b", pattern: "a/../../*", glob: "root/*"},
		{prefix: "root", key: "", name: "root", rel: "", pattern: "", glob: "root"},
		{prefix: "a/b", key: "../c", name: "a/b/c", rel: "c", pattern: "../c", glob: "a/b/c"},
		{prefix: "/", key: "x", name: "/x", rel: "x", pattern: "*", glob: "/*"},
		{prefix: "/", key: "../x", name: "/x", rel: "x", pattern: "../*", glob: "/*"},
		{prefix: "/app/", key: "x", name: "/app/x", rel: "x", pattern: "*", glob: "/app/*"},
		{prefix: ".", key: "x", name: "x", rel: "x", pattern: "*", glob: "*"},
		// glob metacharacters in the prefix match literally
		{prefix: `m*[1]?\`, key: "k", name: `m*[1]?\/k`, rel: "k", pattern: "k*", glob: `m\*\[1\]\?\\/k*`},
	}
	for _, tc := range tcases {
		t.Run(tc.prefix+"|"+tc.key, func(t *testing.T) {
			ns := newNamespace(tc.prefix)
			assert.Equal(t, tc.name, ns.key(tc.key))
			assert.Equal(t, tc.rel, ns.rel(tc.name))
			assert.Equal(t, tc.glob, ns.pattern(tc.pattern))
			assert.Equal(t, tc.rel != "", globMatch(ns.pattern("*"), tc.name),
				"every key but the prefix itself matches *")
		})
	}
}

func TestNamespaceListed(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		prefix  string
		pattern string
		name    string
		key     string
		listed  bool
	}{
		{prefix: "root", pattern: "*", name: "root/x", key: "x", listed: true},
		{prefix: "root", pattern: "", name: "root", key: "", listed: true},
		// not the stored name of any key: written by another client
		{prefix: "root", pattern: "*", name: "root/a//b"},
		{prefix: "root", pattern: "*", name: "root/x/"},
		// '*' matches the entry of "" only under "/"; it is not listed
		{prefix: "/", pattern: "*", name: "/"},
		{prefix: "/", pattern: "", name: "/", key: "", listed: true},
		{prefix: "/", pattern: "*", name: "/x", key: "x", listed: true},
		// a prefix that cleans to "." stores relative names only
		{prefix: ".", pattern: "*", name: "x", key: "x", listed: true},
		{prefix: ".", pattern: "*", name: "/foo"},
	}
	for _, tc := range tcases {
		key, listed := newNamespace(tc.prefix).listed(tc.pattern, tc.name)
		assert.Equal(t, tc.listed, listed, "%s %q %q", tc.prefix, tc.pattern, tc.name)
		assert.Equal(t, tc.key, key, "%s %q %q", tc.prefix, tc.pattern, tc.name)
	}
}

func TestEscapeGlob(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		in  string
		out string
	}{
		{in: "", out: ""},
		{in: "plain/key:1", out: "plain/key:1"},
		{in: `a*b?c[d]e\f`, out: `a\*b\?c\[d\]e\\f`},
	}
	for _, tc := range tcases {
		assert.Equal(t, tc.out, escapeGlob(tc.in))
		assert.True(t, globMatch(escapeGlob(tc.in), tc.in), tc.in)
	}
	// an escaped prefix does not match a sibling its metacharacters would
	assert.False(t, globMatch(escapeGlob("ns*[1]?")+"/*", "nsX1Y/k"))
	assert.True(t, globMatch("ns*[1]?/*", "nsX1Y/k"))
}

// TestGlobMatch covers the Redis glob semantics that differ from path.Match
// and the quirks of the Redis matcher; TestProvider/keys parity compares
// the memory and Redis providers on a real server.
func TestGlobMatch(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		pattern string
		s       string
		match   bool
	}{
		{pattern: "", s: "", match: true},
		{pattern: "", s: "a", match: false},
		// stringmatchlen quirk: '*' does not match the empty string (KEYS
		// and SCAN special-case a lone '*'; a namespaced glob is never one)
		{pattern: "*", s: "", match: false},
		{pattern: "*", s: "a/b/c", match: true},
		{pattern: "a*", s: "a", match: true},
		{pattern: "a**", s: "a", match: true},
		{pattern: "a/*", s: "a/b/c", match: true},
		{pattern: "*/c", s: "a/b/c", match: true},
		{pattern: "a?", s: "a", match: false},
		{pattern: "a?", s: "a/", match: true},
		{pattern: "?", s: "é", match: false}, // two bytes
		{pattern: "??", s: "é", match: true},
		{pattern: "h*llo", s: "hllo", match: true},
		{pattern: "h*llo", s: "heeello", match: true},
		{pattern: "h*llo", s: "hello!", match: false},
		{pattern: "*a*b", s: "xaxb", match: true},
		{pattern: "*a*b", s: "xaxc", match: false},
		{pattern: "user:*:profile", s: "user:22:profile", match: true},
		{pattern: "user:*:profile", s: "user:1:settings", match: false},
		{pattern: "[abc]", s: "b", match: true},
		{pattern: "[abc]", s: "d", match: false},
		{pattern: "[^abc]", s: "b", match: false},
		{pattern: "[^abc]", s: "d", match: true},
		{pattern: "[a-c]x", s: "bx", match: true},
		{pattern: "[c-a]x", s: "bx", match: true}, // reversed range
		{pattern: "[a-c]x", s: "dx", match: false},
		{pattern: `[\]]`, s: "]", match: true},
		{pattern: `[\-]`, s: "-", match: true},
		{pattern: `\*`, s: "*", match: true},
		{pattern: `\*`, s: "a", match: false},
		{pattern: `a\`, s: `a\`, match: true}, // trailing backslash is literal
		{pattern: `x\\y`, s: `x\y`, match: true},
		{pattern: "[ab", s: "b", match: true}, // unterminated set
	}
	for _, tc := range tcases {
		assert.Equal(t, tc.match, globMatch(tc.pattern, tc.s), "%q ~ %q", tc.pattern, tc.s)
	}
}

func TestGlobMatchBacktracking(t *testing.T) {
	t.Parallel()
	// without the skip-longer-matches bound this pattern backtracks
	// exponentially over the string
	pattern := strings.Repeat("a*", 30) + "b"
	s := strings.Repeat("a", 200)
	start := time.Now()
	assert.False(t, globMatch(pattern, s))
	assert.Less(t, time.Since(start), time.Second)

	// nesting deeper than Redis allows does not match
	deep := strings.Repeat("*a", globMaxNesting+1)
	assert.False(t, globMatch(deep, strings.Repeat("a", globMaxNesting+1)))
	assert.True(t, globMatch(strings.Repeat("*a", 10), strings.Repeat("a", 10)))
}
