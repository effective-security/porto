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
	"cmp"
	"crypto/tls"
	"slices"

	"github.com/cockroachdb/errors"
)

// cipherSuiteAliases maps the crypto/tls alias constant names, which
// tls.CipherSuites does not report, to the names it reports.
var cipherSuiteAliases = map[string]string{
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

// The cipher suite tables are derived from the Go release the binary is
// built with, so a suite Go moves to tls.InsecureCipherSuites is rejected
// after a toolchain upgrade.
var (
	// cipherSuites maps the names of the configurable suites (those
	// tls.CipherSuites lists for TLS 1.0-1.2, plus cipherSuiteAliases) to
	// their IDs.
	cipherSuites = map[string]uint16{}
	// tls13CipherSuites holds the TLS 1.3 suite names; Go ignores them in
	// tls.Config.CipherSuites.
	tls13CipherSuites = map[string]bool{}
	// insecureCipherSuites holds the names in tls.InsecureCipherSuites.
	insecureCipherSuites = map[string]bool{}
)

func init() {
	for _, cs := range tls.CipherSuites() {
		if slices.ContainsFunc(cs.SupportedVersions, func(v uint16) bool { return v < tls.VersionTLS13 }) {
			cipherSuites[cs.Name] = cs.ID
		} else {
			tls13CipherSuites[cs.Name] = true
		}
	}
	for alias, name := range cipherSuiteAliases {
		if id, ok := cipherSuites[name]; ok {
			cipherSuites[alias] = id
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		insecureCipherSuites[cs.Name] = true
	}
}

// GetCipherSuite returns the ID for a cipher suite name such as
// "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" and whether UpdateCipherSuites
// accepts it: the name must be a TLS 1.0-1.2 suite that crypto/tls
// implements and does not list in tls.InsecureCipherSuites.
func GetCipherSuite(s string) (uint16, bool) {
	v, ok := cipherSuites[s]
	return v, ok
}

// cipherSuiteID returns the ID of an accepted suite, or an error saying why
// the name is rejected. An alias is classified by the name it stands for.
func cipherSuiteID(name string) (uint16, error) {
	if id, ok := cipherSuites[name]; ok {
		return id, nil
	}
	canonical := cmp.Or(cipherSuiteAliases[name], name)
	switch {
	case insecureCipherSuites[canonical]:
		return 0, errors.Errorf("insecure TLS cipher suite %q", name)
	case tls13CipherSuites[canonical]:
		return 0, errors.Errorf("TLS 1.3 cipher suite %q is not configurable", name)
	default:
		return 0, errors.Errorf("unexpected TLS cipher suite %q", name)
	}
}

// UpdateCipherSuites sets cfg.CipherSuites, the enabled TLS 1.0-1.2 suites,
// from names. It restricts which suites can be negotiated, not their
// preference: Go ignores the order of tls.Config.CipherSuites, and
// PreferServerCipherSuites has no effect. An empty list is a no-op.
// Names are checked like GetCipherSuite; it returns an error, leaving cfg
// unchanged, if CipherSuites is already set or a name is unknown, insecure
// or a TLS 1.3 suite (TLS 1.3 suites are not configurable in Go).
func UpdateCipherSuites(cfg *tls.Config, ss []string) error {
	if len(ss) == 0 {
		// nothing to update
		return nil
	}

	if len(cfg.CipherSuites) > 0 {
		return errors.Errorf("TLSInfo.CipherSuites is already specified (given %v)", ss)
	}

	cs := make([]uint16, len(ss))
	for i, s := range ss {
		id, err := cipherSuiteID(s)
		if err != nil {
			return err
		}
		cs[i] = id
	}
	cfg.CipherSuites = cs

	return nil
}
