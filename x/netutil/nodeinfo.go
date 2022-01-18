package netutil

import (
	"os"

	"github.com/pkg/errors"
)

// NodeInfo is an interface to provide host and IP address for the node in the cluster.
type NodeInfo interface {
	HostName() string
	LocalIP() string
	NodeName() string
}

// GetNodeNameFn is an interface to return an application specific
// node name from the host name.
type GetNodeNameFn func(hostname string) string

type localNodeInfo struct {
	hostname string
	ipAddr   string
	// nodename is derived from the host name,
	// for example, by trimming www. prefix  and .com suffix
	nodename string
}

// NewNodeInfo constructs node info using provided extractor function.
// If extractor is nil, then host name is used.
func NewNodeInfo(extractor GetNodeNameFn) (NodeInfo, error) {
	var err error
	localInfo := new(localNodeInfo)
	if localInfo.hostname, err = os.Hostname(); err != nil {
		return nil, errors.WithMessagef(err, "unable to determine hostname")
	}

	if localInfo.ipAddr, err = GetLocalIP(); err != nil {
		return nil, errors.WithMessagef(err, "unable to determine local IP address")
	}

	localInfo.nodename = localInfo.hostname
	if extractor != nil {
		localInfo.nodename = extractor(localInfo.hostname)
	}

	return localInfo, nil
}

// HostName return a host name
func (l *localNodeInfo) HostName() string {
	return l.hostname
}

// LocalIP return local IP address
func (l *localNodeInfo) LocalIP() string {
	return l.ipAddr
}

// NodeName returns node name derived from hostname
func (l *localNodeInfo) NodeName() string {
	return l.nodename
}
