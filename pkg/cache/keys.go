package cache

import (
	"path"
	"strings"
)

// namespace maps provider-relative keys and patterns to the names stored
// under a prefix and back. The memory and Redis providers use the same
// mapping, so they store, match and list the same names.
type namespace struct {
	// prefix is joined in front of every key.
	prefix string
	// glob is prefix with its glob metacharacters escaped.
	glob string
	// base is the cleaned prefix, which every stored name equals or
	// starts with followed by "/".
	base string
}

func newNamespace(prefix string) namespace {
	return namespace{
		prefix: prefix,
		glob:   escapeGlob(prefix),
		base:   path.Clean(prefix),
	}
}

// key returns the stored name of key. key is cleaned as a rooted path
// before it is joined, so "x", "/x" and "x/" name the same entry and ".."
// cannot leave the prefix: "../x" names "<prefix>/x".
func (n namespace) key(key string) string {
	return path.Join(n.prefix, path.Clean("/"+key))
}

// pattern returns the glob that matches the stored names of the keys that
// pattern matches relative to the prefix: pattern is cleaned like a key and
// the prefix matches literally.
func (n namespace) pattern(pattern string) string {
	return path.Join(n.glob, path.Clean("/"+pattern))
}

// rel returns the provider-relative key of a stored name: the inverse of key
// for cleaned keys, without a leading slash, and "" for the prefix itself.
func (n namespace) rel(name string) string {
	switch {
	case n.base == "/":
		return strings.TrimPrefix(name, "/")
	case name == n.base:
		return ""
	default:
		return strings.TrimPrefix(name, n.base+"/")
	}
}

// listed returns the relative key of a stored name that the glob of
// pattern matched, and false when Keys must not list it: the name is not
// the stored name of any key (another client wrote it, or it lies outside
// a prefix that cleans to "."), or it is the entry of the key "" while
// pattern is not empty ('*' matches that entry only under the prefix "/").
func (n namespace) listed(pattern, name string) (string, bool) {
	key := n.rel(name)
	if n.key(key) != name || (key == "" && path.Clean("/"+pattern) != "/") {
		return "", false
	}
	return key, true
}

// globMeta lists the bytes that are special in a Redis glob pattern.
const globMeta = `*?[]\`

// escapeGlob escapes the Redis glob metacharacters in s, so that a pattern
// starting with the result matches s literally. pkg/redisclient has a copy.
func escapeGlob(s string) string {
	if !strings.ContainsAny(s, globMeta) {
		return s
	}
	var b strings.Builder
	for i := range len(s) {
		if strings.IndexByte(globMeta, s[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// globMaxNesting bounds the recursion of globMatch, as in Redis.
const globMaxNesting = 1000

// globMatch reports whether s matches the Redis glob pattern, following
// the byte-wise stringmatchlen of the Redis server, so that the memory
// provider lists the same keys as Redis KEYS: '*' matches any bytes,
// including '/', '?' matches one byte, "[...]" matches one byte of a set
// with '^' negation and "a-z" ranges, and '\' escapes the next byte.
// Range bounds compare as unsigned bytes; Redis builds where char is
// signed (x86) order bytes >= 0x80 below ASCII, so ranges that mix them
// with ASCII can match differently there.
func globMatch(pattern, s string) bool {
	skipLonger := false
	return globMatchAt(pattern, s, &skipLonger, 0)
}

// globMatchAt is the recursive part of globMatch. skipLonger is set when the
// rest of the pattern after a '*' matches nowhere in the rest of s: then no
// earlier '*' can match either, which bounds the backtracking.
func globMatchAt(p, s string, skipLonger *bool, nesting int) bool {
	if nesting > globMaxNesting {
		return false
	}
	// at returns the pattern byte at i, or 0 past its end (the C code
	// reads the terminating NUL there)
	at := func(i int) byte {
		if i < len(p) {
			return p[i]
		}
		return 0
	}

	pi, si := 0, 0
	for pi < len(p) && si < len(s) {
		switch p[pi] {
		case '*':
			for at(pi+1) == '*' {
				pi++
			}
			if pi == len(p)-1 {
				return true
			}
			for si < len(s) {
				if globMatchAt(p[pi+1:], s[si:], skipLonger, nesting+1) {
					return true
				}
				if *skipLonger {
					return false
				}
				si++
			}
			*skipLonger = true
			return false
		case '?':
			si++
		case '[':
			pi++
			not := at(pi) == '^'
			if not {
				pi++
			}
			match := false
			for {
				if at(pi) == '\\' && len(p)-pi >= 2 {
					pi++
					if p[pi] == s[si] {
						match = true
					}
				} else if at(pi) == ']' {
					break
				} else if pi >= len(p) {
					// unterminated set: the last pattern byte closes it
					pi--
					break
				} else if len(p)-pi >= 3 && p[pi+1] == '-' {
					start, end := p[pi], p[pi+2]
					if start > end {
						start, end = end, start
					}
					pi += 2
					if s[si] >= start && s[si] <= end {
						match = true
					}
				} else if p[pi] == s[si] {
					match = true
				}
				pi++
			}
			if not {
				match = !match
			}
			if !match {
				return false
			}
			si++
		case '\\':
			if len(p)-pi >= 2 {
				pi++
			}
			fallthrough
		default:
			if p[pi] != s[si] {
				return false
			}
			si++
		}
		pi++
		if si == len(s) {
			for at(pi) == '*' {
				pi++
			}
			break
		}
	}
	return pi == len(p) && si == len(s)
}
