package retriable_test

import (
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Factory(t *testing.T) {
	_, err := retriable.LoadFactory("testdata/client_notfound.yaml")
	assert.EqualError(t, err, "failed to load config: open testdata/client_notfound.yaml: no such file or directory")
	_, err = retriable.LoadFactory("testdata/clients_invalid.yaml")
	assert.EqualError(t, err, "failed to parse config: yaml: unmarshal errors:\n  line 2: cannot unmarshal !!seq into map[string]retriable.ClientConfig")

	f, err := retriable.LoadFactory("testdata/clients.yaml")
	require.NoError(t, err)

	_, err = f.CreateClient("prod")
	assert.EqualError(t, err, "failed to load TLS config: open /etc/pki/cabundle.pem: no such file or directory")

	_, err = f.CreateClient("local_https")
	assert.NoError(t, err)
	_, err = f.CreateClient("local_http")
	assert.NoError(t, err)

	_, err = f.CreateClient("default")
	assert.NoError(t, err)
}

func Test_Load(t *testing.T) {
	_, err := retriable.LoadClient("testdata/client_notfound.yaml")
	assert.EqualError(t, err, "failed to load config: open testdata/client_notfound.yaml: no such file or directory")

	c, err := retriable.LoadClient("testdata/client.yaml")
	require.NoError(t, err)
	assert.Equal(t, "https://localhost:4000", c.CurrentHost())

	pol := c.Policy
	assert.Equal(t, 2*time.Second, pol.RequestTimeout)
	assert.Equal(t, 3, pol.TotalRetryLimit)
}
