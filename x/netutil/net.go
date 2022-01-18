package netutil

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// namedAddress represents a TCP Network address based on host name rather
// than IP address. it implements the net.Addr interface, and is used to
// define the node identity to raft.
type namedAddress struct {
	network string
	host    string
	port    uint16
}

// newNamedAddress verifies that the supplied net/host name is resolvable and
// if so returns a namedAddress that represents it, otherwise the resolve
// error is returned
func newNamedAddress(network, host string, port uint16) (*namedAddress, error) {
	na := &namedAddress{network: network, host: host, port: port}
	_, err := na.Resolve()
	if err != nil {
		na = nil
	}
	return na, err
}

// Network() is part of the net.Addr interface
func (a *namedAddress) Network() string {
	return a.network
}

// String() is part of the net.Addr interface
func (a *namedAddress) String() string {
	return fmt.Sprintf("%v:%v", a.host, a.port)
}

// Resolve() resolves this named address to a specific TCP Address.
func (a *namedAddress) Resolve() (*net.TCPAddr, error) {
	return net.ResolveTCPAddr(a.Network(), a.String())
}

// IsAddrInUse checks whether the given error indicates "address in use"
func IsAddrInUse(err error) bool {
	if err, ok := err.(*net.OpError); ok {
		if err, ok := err.Err.(*os.SyscallError); ok {
			return err.Err == syscall.EADDRINUSE
		}
	}
	return false
}
