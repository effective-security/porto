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
	"github.com/effective-security/xlog"
)

// keepAliveConfig is applied to every connection accepted by a keepalive
// listener. A dead peer is detected after Idle + Count*Interval (165s).
var keepAliveConfig = net.KeepAliveConfig{
	Enable:   true,
	Idle:     30 * time.Second,
	Interval: 15 * time.Second,
	Count:    9,
}

// keepAliveConn is implemented by *net.TCPConn.
type keepAliveConn interface {
	SetKeepAliveConfig(config net.KeepAliveConfig) error
}

// NewKeepAliveListener wraps l so that accepted connections get TCP
// keepalive: 30s idle, then up to 9 probes 15s apart. With scheme "https"
// the connection is also wrapped with tls.Server(tlscfg) (handshake happens
// lazily on first I/O) and tlscfg must be non-nil, otherwise an error is
// returned. Connections without SetKeepAliveConfig (*net.TCPConn has it;
// Unix sockets do not) are returned without keepalive; a failure to set the
// socket options is logged and the connection is still returned, as
// net.TCPListener does for its default keepalive. Accept errors of l are
// returned unchanged, so callers such as net/http, grpc and cmux can still
// retry temporary errors. Be careful when wrapping the returned listener
// with another listener: packages like net/http expect Accept to return
// *tls.Conn.
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
		// Not wrapped: net/http, grpc and cmux assert net.Error on the
		// returned value to retry temporary errors such as EMFILE.
		return nil, err
	}
	setKeepAlive(c)
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
		// Not wrapped: see keepaliveListener.Accept.
		return nil, err
	}
	setKeepAlive(c)
	return tls.Server(c, l.config), nil
}

// newTLSKeepaliveListener creates a listener which accepts connections from
// inner, enables keepalive and wraps each connection with tls.Server.
// config must be non-nil and must provide a certificate (Certificates,
// GetCertificate or GetConfigForClient).
func newTLSKeepaliveListener(inner net.Listener, config *tls.Config) net.Listener {
	return &tlsKeepaliveListener{
		Listener: inner,
		config:   config,
	}
}

// setKeepAlive applies keepAliveConfig to c when c supports it. A failure
// does not fail Accept: the peer may already have reset the connection,
// and an Accept error would stop the caller's serve loop.
func setKeepAlive(c net.Conn) {
	kac, ok := c.(keepAliveConn)
	if !ok {
		return
	}
	if err := kac.SetKeepAliveConfig(keepAliveConfig); err != nil {
		logger.KV(xlog.DEBUG,
			"reason", "set_keepalive",
			"remote", c.RemoteAddr(),
			"err", err.Error(),
		)
	}
}
