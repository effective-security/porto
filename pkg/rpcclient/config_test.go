package rpcclient_test

import (
	"crypto/tls"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/porto/pkg/rpcclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authTokenFile is the token file name used by retriable.Storage.
const authTokenFile = ".auth_token"

// unsetEnv clears name for the rest of the test; t.Setenv restores it.
func unsetEnv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	require.NoError(t, os.Unsetenv(name))
}

func TestConfigCheckAuthTokenFromEnv(t *testing.T) {
	const env = "PORTO_RPCCLIENT_TEST_CHECK_TOKEN"

	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()

	tcs := []struct {
		name      string
		value     *string
		expOK     bool
		expErr    string
		expToken  string
		expExpiry int64
	}{
		{
			name:  "unset",
			expOK: false,
		},
		{
			name:  "empty",
			value: new(""),
			expOK: false,
		},
		{
			name:     "opaque",
			value:    new("opaque-token"),
			expOK:    true,
			expToken: "opaque-token",
		},
		{
			name:      "form with expiry",
			value:     new("access_token=form-token&exp=" + strconv.FormatInt(future, 10)),
			expOK:     true,
			expToken:  "form-token",
			expExpiry: future,
		},
		{
			name:   "malformed expiry",
			value:  new("access_token=form-token&exp=soon"),
			expOK:  true,
			expErr: `invalid auth token: invalid exp value: strconv.ParseInt: parsing "soon": invalid syntax`,
		},
		{
			name:   "expired",
			value:  new("access_token=form-token&exp=" + strconv.FormatInt(past, 10)),
			expOK:  true,
			expErr: "auth token expired",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == nil {
				unsetEnv(t, env)
			} else {
				t.Setenv(env, *tc.value)
			}

			cfg := &rpcclient.Config{}
			ok, err := cfg.CheckAuthTokenFromEnv(env)
			assert.Equal(t, tc.expOK, ok)
			if tc.expErr != "" {
				require.EqualError(t, err, tc.expErr)
				assert.Nil(t, cfg.AuthToken)
				assert.Empty(t, cfg.TokenLocation)
				return
			}
			require.NoError(t, err)
			if tc.expToken == "" {
				assert.Nil(t, cfg.AuthToken)
				assert.Empty(t, cfg.TokenLocation)
				return
			}
			require.NotNil(t, cfg.AuthToken)
			assert.Equal(t, tc.expToken, cfg.AuthToken.AccessToken)
			assert.Equal(t, "Bearer", cfg.AuthToken.TokenType)
			assert.Equal(t, *tc.value, cfg.AuthToken.Raw)
			assert.Equal(t, "env://"+env, cfg.TokenLocation)
			if tc.expExpiry == 0 {
				assert.Nil(t, cfg.AuthToken.Expires)
			} else {
				require.NotNil(t, cfg.AuthToken.Expires)
				assert.Equal(t, tc.expExpiry, cfg.AuthToken.Expires.Unix())
			}
		})
	}
}

func TestConfigLoadAuthTokenOrFromEnv(t *testing.T) {
	const env = "PORTO_RPCCLIENT_TEST_LOAD_TOKEN"

	withFile := t.TempDir()
	tokenFile := filepath.Join(withFile, authTokenFile)
	require.NoError(t, os.WriteFile(tokenFile, []byte("file-token"), 0o600))
	withoutFile := t.TempDir()

	tcs := []struct {
		name        string
		env         string
		folder      string
		expErr      string
		expIs       error
		expToken    string
		expLocation string
	}{
		{
			name:        "environment wins over file",
			env:         "env-token",
			folder:      withFile,
			expToken:    "env-token",
			expLocation: "env://" + env,
		},
		{
			name:   "invalid environment does not fall back",
			env:    "exp=never",
			folder: withFile,
			expErr: `invalid auth token: invalid exp value: strconv.ParseInt: parsing "never": invalid syntax`,
		},
		{
			name:        "file without environment",
			folder:      withFile,
			expToken:    "file-token",
			expLocation: tokenFile,
		},
		{
			name:   "neither",
			folder: withoutFile,
			expErr: "credentials not found: open " + filepath.Join(withoutFile, authTokenFile) + ": no such file or directory",
			expIs:  fs.ErrNotExist,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env == "" {
				unsetEnv(t, env)
			} else {
				t.Setenv(env, tc.env)
			}

			cfg := &rpcclient.Config{StorageFolder: tc.folder}
			err := cfg.LoadAuthTokenOrFromEnv(env)
			if tc.expErr != "" {
				require.EqualError(t, err, tc.expErr)
				if tc.expIs != nil {
					assert.ErrorIs(t, err, tc.expIs)
				}
				assert.Nil(t, cfg.AuthToken)
				assert.Empty(t, cfg.TokenLocation)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cfg.AuthToken)
			assert.Equal(t, tc.expToken, cfg.AuthToken.AccessToken)
			assert.Equal(t, tc.expLocation, cfg.TokenLocation)
		})
	}
}

func TestConfigLoadAuthTokenKeepsExpiredToken(t *testing.T) {
	t.Parallel()

	folder := t.TempDir()
	past := time.Now().Add(-time.Hour).Unix()
	location, err := retriable.NewStorage(folder).SaveAuthToken("access_token=old&exp=" + strconv.FormatInt(past, 10))
	require.NoError(t, err)

	// LoadAuthToken does not check expiry; New does
	cfg := &rpcclient.Config{
		Endpoint:      "https://127.0.0.1:1",
		StorageFolder: folder,
		TLS:           &tls.Config{MinVersion: tls.VersionTLS12},
	}
	require.NoError(t, cfg.LoadAuthToken())
	require.NotNil(t, cfg.AuthToken)
	assert.Equal(t, "old", cfg.AuthToken.AccessToken)
	assert.True(t, cfg.AuthToken.Expired())
	assert.Equal(t, location, cfg.TokenLocation)

	client, err := rpcclient.New(cfg)
	require.Nil(t, client)
	require.EqualError(t, err, "authorization: token expired")
}

func TestConfigStorage(t *testing.T) {
	t.Parallel()

	folder := t.TempDir()
	cfg := &rpcclient.Config{StorageFolder: folder}

	storage := cfg.Storage()
	require.NotNil(t, storage)
	assert.Equal(t, folder, storage.Folder())
	assert.Same(t, storage, cfg.Storage(), "Storage is created once")

	// a later StorageFolder change does not replace the created storage
	cfg.StorageFolder = t.TempDir()
	assert.Same(t, storage, cfg.Storage())

	other := t.TempDir()
	_, err := retriable.NewStorage(other).SaveAuthToken("other-token")
	require.NoError(t, err)

	replacement := retriable.NewStorage(other)
	cfg.SetStorage(replacement)
	assert.Same(t, replacement, cfg.Storage())

	// LoadAuthToken reads the storage set with SetStorage
	require.NoError(t, cfg.LoadAuthToken())
	assert.Equal(t, "other-token", cfg.AuthToken.AccessToken)
	assert.Equal(t, filepath.Join(other, authTokenFile), cfg.TokenLocation)
}
