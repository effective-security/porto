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
	"go/importer"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCipherSuites(t *testing.T) {
	pkg, err := importer.For("source", nil).Import("crypto/tls")
	require.NoError(t, err)

	cm := make(map[string]uint16)
	for _, s := range pkg.Scope().Names() {
		if strings.HasPrefix(s, "TLS_RSA_") || strings.HasPrefix(s, "TLS_ECDHE_") {
			v, ok := GetCipherSuite(s)
			require.True(t, ok, "Go implements missing cipher suite %q (%v)", s, v)

			cm[s] = v
		}
	}
	require.Equal(t, cipherSuites, cm)
}

func TestUpdateCipherSuites(t *testing.T) {
	cfg := &tls.Config{}
	assert.NoError(t, UpdateCipherSuites(cfg, []string{}))

	err := UpdateCipherSuites(cfg, []string{"not_found"})
	require.Error(t, err)
	assert.Equal(t, "unexpected TLS cipher suite \"not_found\"", err.Error())

	err = UpdateCipherSuites(cfg, []string{"TLS_RSA_WITH_RC4_128_SHA"})
	assert.NoError(t, err)

	err = UpdateCipherSuites(cfg, []string{"TLS_RSA_WITH_RC4_128_SHA"})
	require.Error(t, err)
	assert.Equal(t, "TLSInfo.CipherSuites is already specified (given [TLS_RSA_WITH_RC4_128_SHA])", err.Error())
}
