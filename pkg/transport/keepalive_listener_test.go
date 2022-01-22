// Copyright 2015 The etcd Authors
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

package transport

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewKeepAliveListener tests NewKeepAliveListener returns a listener
// that accepts connections.
// TODO: verify the keepalive option is set correctly
func TestNewKeepAliveListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tlsInfo := &TLSInfo{
		CertFile:      serverCertFile,
		KeyFile:       serverKeyFile,
		TrustedCAFile: serverRootFile,
		CipherSuites:  []string{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
	}
	defer tlsInfo.Close()
	cfg, err := tlsInfo.ServerTLSWithReloader()
	require.NoError(t, err)

	tlsln, err := NewKeepAliveListener(ln, "https", cfg)
	require.NoError(t, err)

	go http.Get("https://" + tlsln.Addr().String())
	conn, err := tlsln.Accept()
	require.NoError(t, err)
	if _, ok := conn.(*tls.Conn); !ok {
		t.Errorf("failed to accept *tls.Conn")
	}
	conn.Close()
	tlsln.Close()
}

func TestNewKeepAliveListenerHTTPEmptyConfig(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ln, err = NewKeepAliveListener(ln, "http", nil)
	require.NoError(t, err)

	go http.Get("http://" + ln.Addr().String())
	conn, err := ln.Accept()
	require.NoError(t, err)

	conn.Close()
	ln.Close()
}

func TestNewKeepAliveListenerTLSEmptyConfig(t *testing.T) {

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	_, err = NewKeepAliveListener(ln, "https", nil)
	require.Error(t, err)

}
