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
	"time"

	"github.com/cockroachdb/errors"
)

type keepAliveConn interface {
	SetKeepAlive(bool) error
	SetKeepAlivePeriod(d time.Duration) error
}

// NewKeepAliveListener wraps l so that accepted connections get TCP keepalive
// enabled with a 30s period. With scheme "https" the connection is also
// wrapped with tls.Server(tlscfg) (handshake happens lazily on first I/O) and
// tlscfg must be non-nil, otherwise an error is returned. Accepted connections
// must implement SetKeepAlive/SetKeepAlivePeriod (e.g. *net.TCPConn) or
// Accept panics. Be careful when wrapping the returned listener with another
// listener: packages like net/http expect Accept to return *tls.Conn.
// See http://tldp.org/HOWTO/TCP-Keepalive-HOWTO/overview.html
func NewKeepAliveListener(l net.Listener, scheme string, tlscfg *tls.Config) (net.Listener, error) {
	if scheme == "https" {
		if tlscfg == nil {
			return nil, errors.Errorf("cannot listen on TLS for given listener without tls.Config")
		}
		return newTLSKeepaliveListener(l, tlscfg), nil
	}

	return &keepaliveListener{
		Listener: l,
	}, nil
}

type keepaliveListener struct{ net.Listener }

func (kln *keepaliveListener) Accept() (net.Conn, error) {
	c, err := kln.Listener.Accept()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	kac := c.(keepAliveConn)
	// detection time: tcp_keepalive_time + tcp_keepalive_probes + tcp_keepalive_intvl
	// default on linux:  30 + 8 * 30
	// default on osx:    30 + 8 * 75
	_ = kac.SetKeepAlive(true)
	_ = kac.SetKeepAlivePeriod(30 * time.Second)
	return c, nil
}

// A tlsKeepaliveListener implements a network listener (net.Listener) for TLS connections.
type tlsKeepaliveListener struct {
	net.Listener
	config *tls.Config
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection c is a *tls.Conn.
func (l *tlsKeepaliveListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	kac := c.(keepAliveConn)
	// detection time: tcp_keepalive_time + tcp_keepalive_probes + tcp_keepalive_intvl
	// default on linux:  30 + 8 * 30
	// default on osx:    30 + 8 * 75
	_ = kac.SetKeepAlive(true)
	_ = kac.SetKeepAlivePeriod(30 * time.Second)
	c = tls.Server(c, l.config)
	return c, nil
}

// newTLSKeepaliveListener creates a listener which accepts connections from
// inner, enables keepalive and wraps each connection with tls.Server.
// config must be non-nil and must have at least one certificate.
func newTLSKeepaliveListener(inner net.Listener, config *tls.Config) net.Listener {
	l := &tlsKeepaliveListener{}
	l.Listener = inner
	l.config = config
	return l
}
