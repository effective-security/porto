package tlsconfig_test

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/tlsconfig"
	"github.com/go-phorce/dolly/testify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_BuildFromFiles(t *testing.T) {
	pemCert, pemKey, err := testify.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	require.NotNil(t, pemCert)
	require.NotNil(t, pemKey)

	tmpDir := filepath.Join(os.TempDir(), "tests", "tlsconfig")
	err = os.MkdirAll(tmpDir, os.ModePerm)
	require.NoError(t, err)

	pemFile := filepath.Join(tmpDir, "BuildFromFiles.pem")
	keyFile := filepath.Join(tmpDir, "BuildFromFiles-key.pem")

	err = ioutil.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = ioutil.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)

	cfg, err := tlsconfig.NewServerTLSFromFiles(pemFile, keyFile, "", tls.RequireAndVerifyClientCert)
	assert.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)

	cfg, err = tlsconfig.NewServerTLSFromFiles(pemFile, keyFile, pemFile, tls.RequireAndVerifyClientCert)
	assert.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)

	cfg, reloader, err := tlsconfig.NewClientTLSWithReloader(pemFile, keyFile, pemFile, 5*time.Second)
	assert.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
	require.NotNil(t, reloader)
	assert.NotNil(t, reloader.Keypair())
	reloader.Close()

	c, k := reloader.CertAndKeyFiles()
	assert.Equal(t, pemFile, c)
	assert.Equal(t, keyFile, k)
}

func Test_RoundTripper(t *testing.T) {
	pemCert, pemKey, err := testify.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	require.NotNil(t, pemCert)
	require.NotNil(t, pemKey)

	pemFile := filepath.Join(os.TempDir(), "test-RoundTripper.pem")
	keyFile := filepath.Join(os.TempDir(), "test-RoundTripper-key.pem")

	err = ioutil.WriteFile(pemFile, pemCert, os.ModePerm)
	require.NoError(t, err)
	err = ioutil.WriteFile(keyFile, pemKey, os.ModePerm)
	require.NoError(t, err)

	h := makeTestHandler(t, "/v1/test", `{}`)
	server := httptest.NewServer(h)
	defer server.Close()

	tr, err := tlsconfig.NewHTTPTransportWithReloader(
		pemFile,
		keyFile,
		"",
		50*time.Millisecond,
		nil,
	)
	require.NoError(t, err)

	time.Sleep(400 * time.Microsecond)

	for i := 0; i < 5; i++ {
		// modify files
		err = ioutil.WriteFile(pemFile, pemCert, os.ModePerm)
		require.NoError(t, err)

		time.Sleep(400 * time.Microsecond)

		r, err := http.NewRequest(http.MethodGet, "/v1/test", nil)
		require.NoError(t, err)

		_, err = tr.RoundTrip(r)
		assert.Error(t, err)
	}
	tr.Close()
}

func makeTestHandler(t *testing.T, expURI, responseBody string) http.Handler {
	h := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expURI, r.RequestURI, "received wrong URI")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, responseBody)
	}
	return http.HandlerFunc(h)
}
