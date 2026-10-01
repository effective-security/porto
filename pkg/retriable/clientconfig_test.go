package retriable_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/xhttp/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tokenEnv = "PORTO_RETRIABLE_TEST_TOKEN"

func unixTime(d time.Duration) string {
	return strconv.FormatInt(time.Now().Add(d).Unix(), 10)
}

func TestCheckAuthTokenFromEnv(t *testing.T) {
	// not parallel: t.Setenv
	future := unixTime(time.Hour)
	tcases := []struct {
		name   string
		value  string
		unset  bool
		found  bool
		access string
		jkt    string
		err    string
	}{
		{name: "unset", unset: true},
		{name: "empty", value: ""},
		{name: "opaque", value: "env-token", found: true, access: "env-token"},
		{
			name:   "form",
			value:  "access_token=at&dpop_jkt=jkt&exp=" + future,
			found:  true,
			access: "at",
			jkt:    "jkt",
		},
		{name: "malformed", value: "access_token=%zz", found: true, err: `invalid auth token: failed to parse token values: invalid URL escape "%zz"`},
		{name: "expired", value: "access_token=at&exp=" + unixTime(-time.Minute), found: true, err: "auth token expired"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv restores the previous value after an Unsetenv too
			t.Setenv(tokenEnv, tc.value)
			if tc.unset {
				require.NoError(t, os.Unsetenv(tokenEnv))
			}
			cfg := &retriable.ClientConfig{}
			found, err := cfg.CheckAuthTokenFromEnv(tokenEnv)
			assert.Equal(t, tc.found, found)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
			if tc.access == "" {
				// nothing is stored when the variable is unset or invalid
				assert.Nil(t, cfg.AuthToken)
				assert.Empty(t, cfg.TokenLocation)
				return
			}
			require.NotNil(t, cfg.AuthToken)
			assert.Equal(t, tc.access, cfg.AuthToken.AccessToken)
			assert.Equal(t, tc.jkt, cfg.AuthToken.DpopJkt)
			assert.Equal(t, tc.value, cfg.AuthToken.Raw)
			assert.Equal(t, "env://"+tokenEnv, cfg.TokenLocation)
		})
	}
}

func TestLoadAuthTokenOrFromEnv(t *testing.T) {
	// not parallel: t.Setenv
	newConfig := func(t *testing.T, fileToken string) *retriable.ClientConfig {
		cfg := &retriable.ClientConfig{StorageFolder: t.TempDir()}
		if fileToken != "" {
			_, err := cfg.Storage().SaveAuthToken(fileToken)
			require.NoError(t, err)
		}
		return cfg
	}

	t.Run("env", func(t *testing.T) {
		t.Setenv(tokenEnv, "env-token")
		cfg := newConfig(t, "file-token")
		require.NoError(t, cfg.LoadAuthTokenOrFromEnv(tokenEnv))
		require.NotNil(t, cfg.AuthToken)
		assert.Equal(t, "env-token", cfg.AuthToken.AccessToken)
		assert.Equal(t, "env://"+tokenEnv, cfg.TokenLocation)
	})

	t.Run("invalid_env_does_not_fall_back", func(t *testing.T) {
		t.Setenv(tokenEnv, "access_token=at&exp=never")
		cfg := newConfig(t, "file-token")
		err := cfg.LoadAuthTokenOrFromEnv(tokenEnv)
		assert.EqualError(t, err, `invalid auth token: invalid exp value: strconv.ParseInt: parsing "never": invalid syntax`)
		assert.Nil(t, cfg.AuthToken)
	})

	t.Run("file", func(t *testing.T) {
		t.Setenv(tokenEnv, "")
		cfg := newConfig(t, "access_token=file-token&refresh_token=rt")
		require.NoError(t, cfg.LoadAuthTokenOrFromEnv(tokenEnv))
		require.NotNil(t, cfg.AuthToken)
		assert.Equal(t, "file-token", cfg.AuthToken.AccessToken)
		assert.Equal(t, "rt", cfg.AuthToken.RefreshToken)
		assert.Equal(t, filepath.Join(cfg.StorageFolder, tokenFile), cfg.TokenLocation)
	})

	t.Run("missing", func(t *testing.T) {
		t.Setenv(tokenEnv, "")
		cfg := newConfig(t, "")
		err := cfg.LoadAuthTokenOrFromEnv(tokenEnv)
		location := filepath.Join(cfg.StorageFolder, tokenFile)
		assert.EqualError(t, err, "credentials not found: open "+location+": no such file or directory")
		assert.Nil(t, cfg.AuthToken)
		assert.Empty(t, cfg.TokenLocation)
	})
}

func TestNewForHost(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	const host = "https://cfg.test:8443"
	missingCA := filepath.Join(dir, "missing-ca.pem")
	cfgFile := filepath.Join(dir, "clients.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(`
clients:
  configured:
    host: `+host+`
    storage_folder: `+filepath.Join(dir, "storage")+`
    request:
      retry_limit: 2
  broken:
    host: https://broken.test
    tls:
      trusted_ca: `+missingCA+`
`), 0600))

	t.Run("configured", func(t *testing.T) {
		t.Parallel()
		c, err := retriable.NewForHost(cfgFile, host)
		require.NoError(t, err)
		assert.Equal(t, host, c.CurrentHost())
		assert.Equal(t, 2, c.Policy.TotalRetryLimit)
		// LoadFactory appends the host folder to the storage folder
		assert.Equal(t, filepath.Join(dir, "storage", "cfg.test_8443"), c.Config.StorageFolder)
	})

	t.Run("unknown_host", func(t *testing.T) {
		t.Parallel()
		c, err := retriable.NewForHost(cfgFile, "https://other.test")
		require.NoError(t, err)
		assert.Equal(t, "https://other.test", c.CurrentHost())
		assert.Equal(t, retriable.DefaultPolicy().TotalRetryLimit, c.Policy.TotalRetryLimit)
	})

	t.Run("missing_config", func(t *testing.T) {
		t.Parallel()
		c, err := retriable.NewForHost(filepath.Join(dir, "missing.yaml"), host)
		require.NoError(t, err)
		assert.Equal(t, host, c.CurrentHost())
		assert.Empty(t, c.Config.StorageFolder)
	})

	t.Run("client_error", func(t *testing.T) {
		t.Parallel()
		c, err := retriable.NewForHost(cfgFile, "https://broken.test")
		assert.EqualError(t, err, "unable to create client: failed to load TLS config: unable to read CA file "+
			missingCA+": open "+missingCA+": no such file or directory")
		assert.Nil(t, c)
	})
}

func TestLoadClientErrors(t *testing.T) {
	// not parallel: t.Setenv
	dir := t.TempDir()
	t.Setenv("PORTO_RETRIABLE_TEST_DIR", dir)

	invalid := filepath.Join(dir, "invalid.yaml")
	require.NoError(t, os.WriteFile(invalid, []byte("host: [unterminated"), 0600))
	_, err := retriable.LoadClient(invalid)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "failed to parse config: "+invalid+": yaml: "), err.Error())

	// TLS paths are expanded before the files are loaded
	withTLS := filepath.Join(dir, "tls.yaml")
	require.NoError(t, os.WriteFile(withTLS, []byte(`
host: https://tls.test
tls:
  trusted_ca: $PORTO_RETRIABLE_TEST_DIR/ca.pem
`), 0600))
	ca := filepath.Join(dir, "ca.pem")
	_, err = retriable.LoadClient(withTLS)
	assert.EqualError(t, err, "failed to load TLS config: unable to read CA file "+ca+": open "+ca+": no such file or directory")

	storage := filepath.Join(dir, "storage.yaml")
	require.NoError(t, os.WriteFile(storage, []byte(`
host: https://storage.test
storage_folder: $PORTO_RETRIABLE_TEST_DIR/creds
`), 0600))
	c, err := retriable.LoadClient(storage)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "creds"), c.Config.StorageFolder)
	assert.Equal(t, filepath.Join(dir, "creds"), c.Config.Storage().Folder())
}

func TestSetAuthorizationErrors(t *testing.T) {
	t.Parallel()

	t.Run("plain_http_is_noop", func(t *testing.T) {
		t.Parallel()
		authorization := make(chan []string, 1)
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			authorization <- r.Header.Values(header.Authorization)
		}))
		defer server.Close()

		folder := t.TempDir()
		storage := retriable.NewStorage(folder)
		_, err := storage.SaveAuthToken("secret-token")
		require.NoError(t, err)
		client, err := retriable.New(retriable.ClientConfig{Host: server.URL})
		require.NoError(t, err)
		require.NoError(t, client.WithStorage(storage).SetAuthorization())
		assert.Nil(t, client.Config.AuthToken, "the token is not loaded for http hosts")

		_, status, err := client.HeadTo(context.Background(), server.URL, "/")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Empty(t, <-authorization)
	})

	t.Run("missing_token", func(t *testing.T) {
		t.Parallel()
		folder := t.TempDir()
		client, err := retriable.New(retriable.ClientConfig{Host: "https://api.test", StorageFolder: folder})
		require.NoError(t, err)
		err = client.SetAuthorization()
		location := filepath.Join(folder, tokenFile)
		assert.EqualError(t, err, "credentials not found: open "+location+": no such file or directory")
	})

	t.Run("missing_dpop_key", func(t *testing.T) {
		t.Parallel()
		folder := t.TempDir()
		storage := retriable.NewStorage(folder)
		vals := url.Values{
			"access_token": {"at"},
			"dpop_jkt":     {"missing-jkt"},
		}
		_, err := storage.SaveAuthToken(vals.Encode())
		require.NoError(t, err)

		client, err := retriable.New(retriable.ClientConfig{Host: "https://api.test", StorageFolder: folder})
		require.NoError(t, err)
		err = client.SetAuthorization()
		keyFile := filepath.Join(folder, "missing-jkt.jwk")
		assert.EqualError(t, err, "unable to load key for DPoP: missing-jkt: open "+keyFile+": no such file or directory")
	})
}
