package retriable

import (
	"crypto"
	"net/url"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/effective-security/porto/xhttp/header"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func Test_Factory(t *testing.T) {
	_, err := LoadFactory("testdata/client_notfound.yaml")
	assert.EqualError(t, err, "failed to load config: open testdata/client_notfound.yaml: no such file or directory")
	_, err = LoadFactory("testdata/clients_invalid.yaml")
	assert.EqualError(t, err, "failed to parse config: yaml: unmarshal errors:\n  line 2: cannot unmarshal !!seq into map[string]*retriable.ClientConfig")
	_, err = LoadFactory("testdata/clients_duplicate.yaml")
	assert.EqualError(t, err, "multiple entries for host: https://localhost:4000")

	f, err := LoadFactory("testdata/clients.yaml")
	require.NoError(t, err)

	_, err = f.CreateClient("prod")
	assert.EqualError(t, err, "failed to load TLS config: open /etc/pki/cabundle.pem: no such file or directory")

	_, err = f.CreateClient("local_https")
	assert.NoError(t, err)
	_, err = f.CreateClient("local_http")
	assert.NoError(t, err)
	_, err = f.ForHost("https://localhost:4000")
	assert.NoError(t, err)

	_, err = f.CreateClient("default")
	assert.NoError(t, err)
}

func Test_Load(t *testing.T) {
	_, err := LoadClient("testdata/client_notfound.yaml")
	assert.EqualError(t, err, "failed to load config: open testdata/client_notfound.yaml: no such file or directory")

	c, err := LoadClient("testdata/client.yaml")
	require.NoError(t, err)
	assert.Equal(t, "https://localhost:4000", c.CurrentHost())

	pol := c.Policy
	assert.Equal(t, 2*time.Second, pol.RequestTimeout)
	assert.Equal(t, 3, pol.TotalRetryLimit)
}

func TestKeys(t *testing.T) {
	client, err := Create(ClientConfig{
		Hosts:         []string{"https://notused"},
		StorageFolder: path.Join(os.TempDir(), "test", "httpclient-keeys"),
	})
	require.NoError(t, err)
	defer os.RemoveAll(client.StorageFolder)

	assert.Panics(t, func() {
		client.SaveKey(nil)
	})

	_, _, err = client.LoadKey("TestKeys")
	assert.EqualError(t, err, "open /tmp/test/httpclient-keeys/TestKeys.jwk: no such file or directory")

	k := &jose.JSONWebKey{
		KeyID: "TestKeys",
	}
	_, err = client.SaveKey(k)
	require.Error(t, err)

	k.Key = []byte(`sym`)

	_, err = client.SaveKey(k)
	require.Error(t, err)

	_, _, err = client.LoadKey("TestKeys")
	assert.EqualError(t, err, "open /tmp/test/httpclient-keeys/TestKeys.jwk: no such file or directory")
}

func TestWithAuthorization(t *testing.T) {
	signer, err := dpop.GenerateKey("issuer")
	require.NoError(t, err)

	dk, err := dpop.GenerateKey("")
	require.NoError(t, err)

	js, err := jwt.NewFromCryptoSigner(signer.Key.(crypto.Signer))
	require.NoError(t, err)

	extra := jwt.MapClaims{}
	dpop.SetCnfClaim(extra, dk.KeyID)

	tk, err := js.Sign(jwt.CreateClaims("", "subj", js.Issuer(), []string{"test"}, time.Hour, extra))
	require.NoError(t, err)

	client, err := Create(ClientConfig{
		Hosts:         []string{"https://notused"},
		StorageFolder: path.Join(os.TempDir(), "test", "httpclient-keeys"),
	})
	require.NoError(t, err)
	defer os.RemoveAll(client.StorageFolder)
	fn, err := client.SaveKey(dk)
	require.NoError(t, err)
	t.Log(fn)

	t.Run("plain", func(t *testing.T) {
		err = client.StoreAuthToken(tk)
		require.NoError(t, err)

		err = client.WithAuthorization()
		require.NoError(t, err)
		assert.Contains(t, client.headers[header.Authorization], "Bearer")
	})

	t.Run("dpop", func(t *testing.T) {
		vals := url.Values{
			"access_token": {tk},
			"dpop_jkt":     {dk.KeyID},
			"exp":          {strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
		}
		err = client.StoreAuthToken(vals.Encode())
		require.NoError(t, err)

		err = client.WithAuthorization()
		require.NoError(t, err)
		assert.Contains(t, client.headers[header.Authorization], "DPoP")
	})

	t.Run("dpop_expired", func(t *testing.T) {
		vals := url.Values{
			"access_token": {tk},
			"dpop_jkt":     {dk.KeyID},
			"exp":          {strconv.FormatInt(time.Now().Unix(), 10)},
		}
		err = client.StoreAuthToken(vals.Encode())
		require.NoError(t, err)

		err = client.WithAuthorization()
		assert.EqualError(t, err, "authorization: token expired")
	})
}
