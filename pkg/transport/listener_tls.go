// Copyright 2017 The etcd Authors
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
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/xhttp/limits"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"golang.org/x/crypto/ocsp"
)

// tlsListener completes each TLS handshake before Accept returns the
// connection and rejects connections that fail check (the CRL check when
// TLSInfo.CRLVerifier is set).
type tlsListener struct {
	net.Listener
	connc chan net.Conn
	// errc passes Accept errors of the inner listener, other than
	// net.ErrClosed, to the next Accept call.
	errc      chan error
	closec    chan struct{} // closed by Close
	closeOnce sync.Once
	donec     chan struct{} // closed when acceptLoop returns
	// err is the error that stopped acceptLoop (it wraps net.ErrClosed); it
	// is read only after donec is closed.
	err              error
	handshakeFailure func(*tls.Conn, error)
	handshakeTimeout time.Duration
	check            tlsCheckFunc
}

type tlsCheckFunc func(context.Context, *tls.Conn) error

// NewTLSListener wraps l so that every accepted connection is TLS-handshaked
// in its own goroutine before Accept returns it; connections that fail the
// handshake or the CRL check (when tlsinfo.CRLVerifier is set) are closed and
// reported to tlsinfo.HandshakeFailure. It calls tlsinfo.ServerTLSWithReloader,
// so the tls.Config is available afterwards via tlsinfo.Config(). If tlsinfo
// is nil or Empty, l is closed and an error returned; if
// ServerTLSWithReloader fails, its error is returned and l is left open.
// The caller must Close the returned listener; Close blocks until the accept
// loop and pending handshakes finish. HandshakeTimeout defaults to 10s; a
// negative value disables it. The deadline is cleared before a successful
// connection is returned.
//
// An Accept error of l other than net.ErrClosed does not stop the listener:
// it is returned unchanged by the next Accept call, so the caller decides
// whether to retry (net/http and grpc back off on temporary errors such as
// EMFILE), and accepting continues after it. A wrapped listener that reports
// its closure with another error, such as a cmux listener, keeps the accept
// loop running until Close; net/http and grpc close the listener when such
// an error stops them.
func NewTLSListener(l net.Listener, tlsinfo *TLSInfo) (net.Listener, error) {
	check := func(context.Context, *tls.Conn) error { return nil }
	return newTLSListener(l, tlsinfo, check)
}

func newTLSListener(l net.Listener, tlsinfo *TLSInfo, check tlsCheckFunc) (net.Listener, error) {
	if tlsinfo == nil || tlsinfo.Empty() {
		l.Close()
		return nil, errors.Errorf("cannot listen on TLS for %s: KeyFile and CertFile are not presented",
			l.Addr().String())
	}

	tlsCfg, err := tlsinfo.ServerTLSWithReloader()
	if err != nil {
		return nil, err
	}

	hf := tlsinfo.HandshakeFailure
	if hf == nil {
		hf = func(*tls.Conn, error) {}
	}

	if tlsinfo.CRLVerifier != nil {
		prevCheck := check
		check = func(ctx context.Context, tlsConn *tls.Conn) error {
			if err := prevCheck(ctx, tlsConn); err != nil {
				return err
			}
			st := tlsConn.ConnectionState()

			for _, chain := range st.VerifiedChains {
				// loop up to the Root, which is the last
				for i, s := 0, len(chain); i < s-1; i++ {
					crt := chain[i]
					st, err := tlsinfo.CRLVerifier.Verify(crt, chain[i+1])
					if err != nil {
						logger.KV(xlog.WARNING,
							"status", "unable_to_verify",
							"serial", crt.SerialNumber.String(),
							"subject", crt.Subject.String(),
							"issuer", crt.Issuer.String(),
							"err", err.Error(),
						)
					} else if st == ocsp.Revoked {
						return errors.Errorf("transport: certificate serial %s revoked", crt.SerialNumber.String())
					} else if st == ocsp.Unknown {
						logger.KV(xlog.DEBUG,
							"status", "unknown",
							"serial", crt.SerialNumber.String(),
							"subject", crt.Subject.String(),
							"issuer", crt.Issuer.String(),
							"ikid", certutil.GetAuthorityKeyID(crt),
						)
					}
				}
			}

			return nil
		}
	}

	tlsl := &tlsListener{
		Listener:         tls.NewListener(l, tlsCfg),
		connc:            make(chan net.Conn),
		errc:             make(chan error),
		closec:           make(chan struct{}),
		donec:            make(chan struct{}),
		handshakeFailure: hf,
		check:            check,
		handshakeTimeout: (limits.Timeouts{Handshake: tlsinfo.HandshakeTimeout}).WithDefaults().Handshake,
	}
	go tlsl.acceptLoop()
	return tlsl, nil
}

// Close closes the inner listener and waits until the accept loop and the
// pending handshakes have finished.
func (l *tlsListener) Close() error {
	l.closeOnce.Do(func() { close(l.closec) })
	err := l.Listener.Close()
	<-l.donec
	return err
}

// Accept returns the next handshaked connection, or the next Accept error of
// the inner listener. After Close, or after the inner listener reported
// net.ErrClosed, it returns an error wrapping net.ErrClosed.
func (l *tlsListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connc:
		return conn, nil
	case err := <-l.errc:
		return nil, err
	case <-l.donec:
		return nil, l.err
	}
}

// acceptLoop launches each TLS handshake in a separate goroutine
// to prevent a hanging TLS connection from blocking other connections.
func (l *tlsListener) acceptLoop() {
	var wg sync.WaitGroup
	var pendingMu sync.Mutex

	pending := make(map[net.Conn]struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		pendingMu.Lock()
		for c := range pending {
			c.Close()
		}
		pendingMu.Unlock()
		wg.Wait()
		close(l.donec)
	}()

	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if stopErr := l.forwardAcceptError(err); stopErr != nil {
				l.err = stopErr
				return
			}
			continue
		}

		pendingMu.Lock()
		pending[conn] = struct{}{}
		pendingMu.Unlock()

		wg.Add(1)
		go func() {
			defer func() {
				if conn != nil {
					conn.Close()
				}
				wg.Done()
			}()

			tlsConn := conn.(*tls.Conn)
			herr := l.handshake(tlsConn)
			pendingMu.Lock()
			delete(pending, conn)
			pendingMu.Unlock()

			if herr != nil {
				l.handshakeFailure(tlsConn, herr)
				return
			}
			if err := l.check(ctx, tlsConn); err != nil {
				l.handshakeFailure(tlsConn, err)
				return
			}

			select {
			case l.connc <- tlsConn:
				conn = nil
			case <-ctx.Done():
			}
		}()
	}
}

// forwardAcceptError hands err to the next Accept call. It returns the
// error that stops the accept loop instead: err itself when the inner
// listener reports that it is closed, or net.ErrClosed when Close was called.
func (l *tlsListener) forwardAcceptError(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return err
	}
	// Checked first: select picks randomly when an Accept call is also waiting.
	select {
	case <-l.closec:
		return errors.WithStack(net.ErrClosed)
	default:
	}
	select {
	case l.errc <- err:
		return nil
	case <-l.closec:
		return errors.WithStack(net.ErrClosed)
	}
}

func (l *tlsListener) handshake(conn *tls.Conn) error {
	if l.handshakeTimeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(l.handshakeTimeout)); err != nil {
			return errors.WithMessage(err, "unable to set TLS handshake deadline")
		}
	}
	if err := conn.Handshake(); err != nil {
		return errors.WithMessage(err, "TLS handshake failed")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return errors.WithMessage(err, "unable to clear TLS handshake deadline")
	}
	return nil
}
