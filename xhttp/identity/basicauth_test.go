package identity

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicAuthFromRequest(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/test", nil)

	id, secret, err := BasicAuthFromRequest(r)
	require.NoError(t, err)
	assert.Empty(t, id)
	assert.Empty(t, secret)

	r.Header.Set("Authorization", "Basic invalid")
	_, _, err = BasicAuthFromRequest(r)
	assert.EqualError(t, err, "invalid_request: invalid Authorization header")

	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(`single`)))
	id, secret, err = BasicAuthFromRequest(r)
	require.NoError(t, err)
	assert.Equal(t, "single", id)
	assert.Empty(t, secret)

	r.SetBasicAuth("", "")
	id, secret, err = BasicAuthFromRequest(r)
	require.NoError(t, err)
	assert.Empty(t, id)
	assert.Empty(t, secret)

	r.SetBasicAuth("nameonly", "")
	id, secret, err = BasicAuthFromRequest(r)
	require.NoError(t, err)
	assert.Equal(t, "nameonly", id)
	assert.Empty(t, secret)

	r.SetBasicAuth("name", "secret")
	id, secret, err = BasicAuthFromRequest(r)
	require.NoError(t, err)
	assert.Equal(t, "name", id)
	assert.Equal(t, "secret", secret)

	r.SetBasicAuth("", "secretonly")
	id, secret, err = BasicAuthFromRequest(r)
	require.NoError(t, err)
	assert.Equal(t, "", id)
	assert.Equal(t, "secretonly", secret)
}
