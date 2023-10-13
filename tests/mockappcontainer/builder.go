package mockappcontainer

import (
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/xpki/jwt"
	"go.uber.org/dig"
)

// Builder helps to build container
type Builder struct {
	container *dig.Container
}

// NewBuilder returns ContainerBuilder
func NewBuilder() *Builder {
	return &Builder{
		container: dig.New(),
	}
}

// Container returns Container
func (b *Builder) Container() *dig.Container {
	return b.container
}

// WithConfig sets gserver.HTTPServerCfg
func (b *Builder) WithConfig(c *gserver.Config) *Builder {
	_ = b.container.Provide(func() *gserver.Config {
		return c
	})
	return b
}

// WithJwtSigner sets JWT Signer
func (b *Builder) WithJwtSigner(j jwt.Signer) *Builder {
	_ = b.container.Provide(func() jwt.Signer {
		return j
	})
	return b
}

// WithJwtParser sets JWT Parser
func (b *Builder) WithJwtParser(j jwt.Parser) *Builder {
	_ = b.container.Provide(func() jwt.Parser {
		return j
	})
	return b
}

// WithDiscovery sets Discover
func (b *Builder) WithDiscovery(d discovery.Discovery) *Builder {
	_ = b.container.Provide(func() discovery.Discovery {
		return d
	})
	return b
}
