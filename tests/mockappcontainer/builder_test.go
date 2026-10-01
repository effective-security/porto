package mockappcontainer

import (
	"testing"

	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubSigner and stubParser are distinct non-nil values to provide; the
// container never calls their methods.
type stubSigner struct{ jwt.Signer }

type stubParser struct{ jwt.Parser }

func TestBuilder(t *testing.T) {
	t.Parallel()

	cfg := &gserver.Config{
		Description: "mock",
	}
	signer := &stubSigner{}
	parser := &stubParser{}
	disco := discovery.New()

	container := NewBuilder().
		WithConfig(cfg).
		WithJwtParser(parser).
		WithJwtSigner(signer).
		WithDiscovery(disco).
		Container()
	require.NotNil(t, container)

	invoked := false
	err := container.Invoke(func(c *gserver.Config, s jwt.Signer, p jwt.Parser, d discovery.Discovery) {
		invoked = true
		assert.Same(t, cfg, c)
		assert.Same(t, signer, s)
		assert.Same(t, parser, p)
		assert.Same(t, disco, d)
	})
	require.NoError(t, err)
	assert.True(t, invoked)
}

func TestBuilderMissingProvider(t *testing.T) {
	t.Parallel()

	container := NewBuilder().Container()
	err := container.Invoke(func(*gserver.Config) {})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "*gserver.Config", "the error names the type without a provider")
}
