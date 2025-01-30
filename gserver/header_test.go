package gserver

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSkipKeys(t *testing.T) {
	opts := &copyOptions{skipKeys: make(map[string]bool)}
	skipKeys("Content-Type", "Authorization")(opts)

	assert.True(t, opts.skipKeys["content-type"])
	assert.True(t, opts.skipKeys["authorization"])
}

func TestReplaceInVals(t *testing.T) {
	opts := &copyOptions{}
	replaceInVals("Content-Type", "application/json", "application/xml")(opts)

	replacedKey, replacedVals, replaced := opts.replacers[0]("Content-Type", []string{"application/json"})
	assert.True(t, replaced)
	assert.Equal(t, "Content-Type", replacedKey)
	require.Len(t, replacedVals, 1)
	assert.Equal(t, "application/xml", replacedVals[0])
}

func TestReplaceInKeys(t *testing.T) {
	opts := &copyOptions{}
	replaceInKeys("Old-Key", "New-Key")(opts)

	replacedKey, _, replaced := opts.replacers[0]("Old-Key", []string{"value"})
	assert.True(t, replaced)
	assert.Equal(t, "New-Key", replacedKey)
}

func TestKeyCase(t *testing.T) {
	opts := &copyOptions{}
	keyCase(strings.ToLower)(opts)

	replacedKey, _, replaced := opts.replacers[0]("Content-Type", []string{"value"})
	assert.True(t, replaced)
	assert.Equal(t, "content-type", replacedKey)
}

func TestCopyHeader(t *testing.T) {
	src := http.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer token"},
	}
	dst := http.Header{}

	copyHeader(dst, src, skipKeys("Authorization"), replaceInVals("Content-Type", "application/json", "application/xml"))

	require.Len(t, dst, 1)
	assert.Equal(t, "application/xml", dst.Get("Content-Type"))
}

func TestHeaderKeys(t *testing.T) {
	// Test that headerKeys returns a sorted list of keys.
	h := http.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer token"},
	}
	keys := headerKeys(h)
	sort.Strings(keys)
	assert.Equal(t, []string{"Authorization", "Content-Type"}, keys)
}
