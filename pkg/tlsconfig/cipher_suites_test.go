// Copyright 2018 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tlsconfig

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCipherSuites(t *testing.T) {
	t.Parallel()

	accepted := map[string]uint16{}
	for _, cs := range tls.CipherSuites() {
		v, ok := GetCipherSuite(cs.Name)
		if cs.SupportedVersions[0] == tls.VersionTLS13 {
			assert.False(t, ok, "TLS 1.3 suite %q is not configurable", cs.Name)
			continue
		}
		require.True(t, ok, "Go implements secure cipher suite %q", cs.Name)
		assert.Equal(t, cs.ID, v)
		accepted[cs.Name] = cs.ID
	}
	for _, cs := range tls.InsecureCipherSuites() {
		_, ok := GetCipherSuite(cs.Name)
		assert.False(t, ok, "insecure cipher suite %q must be rejected", cs.Name)
	}

	// The CHACHA20 aliases are crypto/tls constants tls.CipherSuites does not name.
	accepted["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"] = tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
	accepted["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"] = tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
	assert.Equal(t, accepted, cipherSuites)

	for _, name := range []string{"", "not_found", "tls_ecdhe_rsa_with_aes_128_gcm_sha256"} {
		v, ok := GetCipherSuite(name)
		assert.False(t, ok, name)
		assert.Zero(t, v, name)
	}
}

func TestUpdateCipherSuites(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		name     string
		suites   []string
		expected []uint16
		err      string
	}{
		{
			name: "nil",
		},
		{
			name:   "empty",
			suites: []string{},
		},
		{
			name: "order preserved",
			suites: []string{
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
				"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			},
			expected: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			},
		},
		{
			name:   "unknown",
			suites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "not_found"},
			err:    `unexpected TLS cipher suite "not_found"`,
		},
		{
			name:   "RC4",
			suites: []string{"TLS_RSA_WITH_RC4_128_SHA"},
			err:    `insecure TLS cipher suite "TLS_RSA_WITH_RC4_128_SHA"`,
		},
		{
			name:   "3DES",
			suites: []string{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
			err:    `insecure TLS cipher suite "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"`,
		},
		{
			name:   "CBC-SHA256",
			suites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
			err:    `insecure TLS cipher suite "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"`,
		},
		{
			name:   "RSA key exchange",
			suites: []string{"TLS_RSA_WITH_AES_128_GCM_SHA256"},
			err:    `insecure TLS cipher suite "TLS_RSA_WITH_AES_128_GCM_SHA256"`,
		},
		{
			name:   "TLS 1.3",
			suites: []string{"TLS_AES_128_GCM_SHA256"},
			err:    `TLS 1.3 cipher suite "TLS_AES_128_GCM_SHA256" is not configurable`,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &tls.Config{}
			err := UpdateCipherSuites(cfg, tc.suites)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				assert.Nil(t, cfg.CipherSuites, "a rejected list leaves the config unchanged")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, cfg.CipherSuites)
		})
	}
}

// An alias whose suite Go lists as insecure is reported as insecure. The
// test edits the package tables, so it must not run in parallel.
func TestCipherSuiteAliasClassification(t *testing.T) {
	const alias = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	canonical := cipherSuiteAliases[alias]
	id := cipherSuites[canonical]
	delete(cipherSuites, alias)
	delete(cipherSuites, canonical)
	insecureCipherSuites[canonical] = true
	t.Cleanup(func() {
		cipherSuites[alias] = id
		cipherSuites[canonical] = id
		delete(insecureCipherSuites, canonical)
	})

	_, err := cipherSuiteID(alias)
	assert.EqualError(t, err, `insecure TLS cipher suite "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"`)
}

func TestUpdateCipherSuitesAlreadySet(t *testing.T) {
	t.Parallel()

	cfg := &tls.Config{}
	suites := []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	require.NoError(t, UpdateCipherSuites(cfg, suites))

	err := UpdateCipherSuites(cfg, []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"})
	require.EqualError(t, err, "TLSInfo.CipherSuites is already specified (given [TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384])")
	assert.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, cfg.CipherSuites)

	// An empty list is a no-op even when the config is already set.
	require.NoError(t, UpdateCipherSuites(cfg, nil))
	assert.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, cfg.CipherSuites)
}
