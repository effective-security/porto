package mockappcontainer

import (
	"testing"

	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/require"
)

func TestBuilder(t *testing.T) {
	container := NewBuilder().
		WithJwtParser(nil).
		WithJwtSigner(nil).
		WithDiscovery(discovery.New()).
		Container()
	require.NotNil(t, container)

	err := container.Invoke(func(jwt.Signer, jwt.Parser, discovery.Discovery) error {
		return nil
	})
	require.NoError(t, err)
}
