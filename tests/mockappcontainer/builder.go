package mockappcontainer

import (
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/xpki/jwt"
	"go.uber.org/dig"
)

// Builder accumulates providers into a dig container for gserver tests.
type Builder struct {
	container *dig.Container
}

// NewBuilder returns a Builder over a new, empty dig container.
func NewBuilder() *Builder {
	return &Builder{
		container: dig.New(),
	}
}

// Container returns the underlying dig container.
func (b *Builder) Container() *dig.Container {
	return b.container
}

// WithConfig provides *gserver.Config.
func (b *Builder) WithConfig(c *gserver.Config) *Builder {
	_ = b.container.Provide(func() *gserver.Config {
		return c
	})
	return b
}

// WithJwtSigner provides jwt.Signer.
func (b *Builder) WithJwtSigner(j jwt.Signer) *Builder {
	_ = b.container.Provide(func() jwt.Signer {
		return j
	})
	return b
}

// WithJwtParser provides jwt.Parser.
func (b *Builder) WithJwtParser(j jwt.Parser) *Builder {
	_ = b.container.Provide(func() jwt.Parser {
		return j
	})
	return b
}

// WithDiscovery provides discovery.Discovery.
func (b *Builder) WithDiscovery(d discovery.Discovery) *Builder {
	_ = b.container.Provide(func() discovery.Discovery {
		return d
	})
	return b
}
