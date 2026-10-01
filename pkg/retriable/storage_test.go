package retriable_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/retriable"
	"github.com/effective-security/xpki/jwt/dpop"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tokenFile = ".auth_token"

// fakeRSAKey returns an RSA private key whose modulus has the given bit
// length; only the public part is set, which is all NewKeyInfo and the
// JWK thumbprint read, so tests avoid generating large keys.
func fakeRSAKey(bits int) *rsa.PrivateKey {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.SetBit(n, 0, 1)
	return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}}
}

func mustECDSA(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return k
}

func thumbprint(t *testing.T, k *jose.JSONWebKey) string {
	t.Helper()
	tp, err := dpop.Thumbprint(k)
	require.NoError(t, err)
	return tp
}

func writeJWK(t *testing.T, path string, k *jose.JSONWebKey) {
	t.Helper()
	data, err := json.Marshal(k)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}

// skipIfRoot skips tests that rely on permission checks, which root bypasses.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
}

func TestNewKeyInfo(t *testing.T) {
	t.Parallel()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p256 := mustECDSA(t, elliptic.P256())

	tcases := []struct {
		name    string
		key     any
		typ     string
		algo    string
		keySize int
		err     string
		// errPart is matched instead of err for go-jose messages
		errPart string
	}{
		{name: "rsa2048", key: fakeRSAKey(2048), typ: "RSA", algo: "RS256", keySize: 2048},
		{name: "rsa3071", key: fakeRSAKey(3071), typ: "RSA", algo: "RS256", keySize: 3071},
		{name: "rsa3072", key: fakeRSAKey(3072), typ: "RSA", algo: "RS384", keySize: 3072},
		{name: "rsa4096", key: fakeRSAKey(4096), typ: "RSA", algo: "RS512", keySize: 4096},
		{name: "p256", key: p256, typ: "ECDSA", algo: "ES256", keySize: 256},
		{name: "p384", key: mustECDSA(t, elliptic.P384()), typ: "ECDSA", algo: "ES384", keySize: 384},
		{name: "p521", key: mustECDSA(t, elliptic.P521()), typ: "ECDSA", algo: "ES512", keySize: 521},
		{name: "ecdsa_public", key: &p256.PublicKey, err: "key not supported: *ecdsa.PublicKey"},
		{name: "ed25519", key: edKey, err: "key not supported: ed25519.PrivateKey"},
		{name: "symmetric", key: []byte("secret"), errPart: "unknown key type"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			k := &jose.JSONWebKey{Key: tc.key}
			ki, err := retriable.NewKeyInfo(k)
			if tc.err != "" || tc.errPart != "" {
				if tc.err != "" {
					assert.EqualError(t, err, tc.err)
				} else {
					assert.ErrorContains(t, err, tc.errPart)
				}
				assert.Nil(t, ki)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.typ, ki.Type)
			assert.Equal(t, tc.algo, ki.Algo)
			assert.Equal(t, tc.keySize, ki.KeySize)
			assert.Same(t, k, ki.Key)
			// the thumbprint is the dpop_jkt value naming the key file
			assert.Equal(t, thumbprint(t, k), ki.Thumbprint)
		})
	}
}

func TestStorageListKeys(t *testing.T) {
	t.Parallel()

	folder := t.TempDir()
	storage := retriable.NewStorage(folder)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256, err := dpop.GenerateKey("")
	require.NoError(t, err)
	p384 := &jose.JSONWebKey{Key: mustECDSA(t, elliptic.P384())}
	rsaJWK := &jose.JSONWebKey{Key: rsaKey}

	type expected struct {
		typ     string
		algo    string
		keySize int
	}
	want := map[string]expected{}
	for _, k := range []*jose.JSONWebKey{p256, p384, rsaJWK} {
		_, err := storage.SaveKey(k)
		require.NoError(t, err)
	}
	want[thumbprint(t, p256)] = expected{typ: "ECDSA", algo: "ES256", keySize: 256}
	want[thumbprint(t, p384)] = expected{typ: "ECDSA", algo: "ES384", keySize: 384}
	want[thumbprint(t, rsaJWK)] = expected{typ: "RSA", algo: "RS256", keySize: 2048}

	// keys in sub-folders are listed too
	p521 := &jose.JSONWebKey{Key: mustECDSA(t, elliptic.P521())}
	_, err = retriable.NewStorage(filepath.Join(folder, "nested", "host")).SaveKey(p521)
	require.NoError(t, err)
	want[thumbprint(t, p521)] = expected{typ: "ECDSA", algo: "ES512", keySize: 521}

	// skipped: wrong suffix, malformed JSON, public and symmetric keys, a
	// folder named like a key, and the token file
	writeJWK(t, filepath.Join(folder, "key.json"), &jose.JSONWebKey{Key: mustECDSA(t, elliptic.P256())})
	require.NoError(t, os.WriteFile(filepath.Join(folder, "broken.jwk"), []byte("{not json"), 0600))
	public := mustECDSA(t, elliptic.P256())
	writeJWK(t, filepath.Join(folder, "public.jwk"), &jose.JSONWebKey{Key: &public.PublicKey})
	writeJWK(t, filepath.Join(folder, "oct.jwk"), &jose.JSONWebKey{Key: []byte("symmetric-secret")})
	require.NoError(t, os.Mkdir(filepath.Join(folder, "dir.jwk"), 0700))
	_, err = storage.SaveAuthToken("token")
	require.NoError(t, err)

	list, err := storage.ListKeys()
	require.NoError(t, err)
	got := map[string]expected{}
	for _, ki := range list {
		got[ki.Thumbprint] = expected{typ: ki.Type, algo: ki.Algo, keySize: ki.KeySize}
		require.NotNil(t, ki.Key)
		assert.True(t, ki.Key.Valid())
		assert.False(t, ki.Key.IsPublic(), "listed keys are private keys")
	}
	assert.Equal(t, want, got)
	assert.Len(t, list, len(want))
}

func TestStorageListKeysMissingFolder(t *testing.T) {
	t.Parallel()

	list, err := retriable.NewStorage(filepath.Join(t.TempDir(), "missing")).ListKeys()
	require.NoError(t, err)
	assert.NotNil(t, list)
	assert.Empty(t, list)
}

func TestStorageListKeysSkipsUnreadableKey(t *testing.T) {
	t.Parallel()
	skipIfRoot(t)

	folder := t.TempDir()
	storage := retriable.NewStorage(folder)
	k, err := dpop.GenerateKey("")
	require.NoError(t, err)
	_, err = storage.SaveKey(k)
	require.NoError(t, err)

	unreadable := filepath.Join(folder, "unreadable.jwk")
	writeJWK(t, unreadable, &jose.JSONWebKey{Key: mustECDSA(t, elliptic.P256())})
	require.NoError(t, os.Chmod(unreadable, 0))

	list, err := storage.ListKeys()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, k.KeyID, list[0].Thumbprint)
}

func TestStorageMarshalUnmarshal(t *testing.T) {
	t.Parallel()

	type document struct {
		Name  string   `json:"name" yaml:"name"`
		Count int      `json:"count" yaml:"count"`
		Tags  []string `json:"tags" yaml:"tags"`
	}
	in := document{Name: "client", Count: 3, Tags: []string{"a", "b"}}

	folder := t.TempDir()
	storage := retriable.NewStorage(folder)

	tcases := []struct {
		file    string
		content string
	}{
		{file: "doc.json", content: `"name": "client"`},
		{file: "doc.yaml", content: "name: client\n"},
	}
	for _, tc := range tcases {
		require.NoError(t, storage.Marshal(tc.file, &in), tc.file)
		data, err := os.ReadFile(filepath.Join(folder, tc.file))
		require.NoError(t, err)
		assert.Contains(t, string(data), tc.content, tc.file)

		var out document
		require.NoError(t, storage.Unmarshal(tc.file, &out), tc.file)
		assert.Equal(t, in, out, tc.file)
	}

	var out document
	err := storage.Unmarshal("missing.json", &out)
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Equal(t, document{}, out)

	// the folder is not created by Marshal
	missing := retriable.NewStorage(filepath.Join(folder, "missing"))
	err = missing.Marshal("doc.json", &in)
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.NoDirExists(t, missing.Folder())
}

func TestParseAuthToken(t *testing.T) {
	t.Parallel()

	exp := time.Unix(1700000000, 0)
	tcases := []struct {
		name    string
		raw     string
		access  string
		refresh string
		jkt     string
		expires *time.Time
		err     string
	}{
		{name: "opaque", raw: "opaque-token", access: "opaque-token"},
		{
			name:    "form",
			raw:     "access_token=at&refresh_token=rt&dpop_jkt=jkt&exp=1700000000",
			access:  "at",
			refresh: "rt",
			jkt:     "jkt",
			expires: &exp,
		},
		{name: "id_token", raw: "id_token=it", access: "it"},
		{name: "token", raw: "token=tk", access: "tk"},
		{name: "access_token_first", raw: "token=tk&id_token=it&access_token=at", access: "at"},
		{name: "id_token_before_token", raw: "token=tk&id_token=it", access: "it"},
		{name: "first_value", raw: "access_token=one&access_token=two", access: "one"},
		{name: "invalid_exp", raw: "access_token=at&exp=soon", err: `invalid exp value: strconv.ParseInt: parsing "soon": invalid syntax`},
		{name: "invalid_query", raw: "access_token=%zz", err: `failed to parse token values: invalid URL escape "%zz"`},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			at, location, err := retriable.ParseAuthToken(tc.raw, "env://TOKEN")
			assert.Equal(t, "env://TOKEN", location)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, at)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.raw, at.Raw)
			assert.Equal(t, "Bearer", at.TokenType)
			assert.Equal(t, tc.access, at.AccessToken)
			assert.Equal(t, tc.refresh, at.RefreshToken)
			assert.Equal(t, tc.jkt, at.DpopJkt)
			if tc.expires == nil {
				assert.Nil(t, at.Expires)
			} else {
				require.NotNil(t, at.Expires)
				assert.True(t, tc.expires.Equal(*at.Expires))
				assert.True(t, at.Expired())
			}
		})
	}
}

func TestLoadAuthTokenMissing(t *testing.T) {
	t.Parallel()

	folder := t.TempDir()
	location := filepath.Join(folder, tokenFile)
	at, file, err := retriable.LoadAuthToken(folder)
	assert.EqualError(t, err, "credentials not found: open "+location+": no such file or directory")
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Nil(t, at)
	assert.Equal(t, location, file)

	at, file, err = retriable.NewStorage(folder).LoadAuthToken()
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Nil(t, at)
	assert.Equal(t, location, file)
}

func TestStorageFolderErrors(t *testing.T) {
	t.Parallel()

	key, err := dpop.GenerateKey("")
	require.NoError(t, err)

	t.Run("folder_is_file", func(t *testing.T) {
		t.Parallel()
		folder := filepath.Join(t.TempDir(), "creds")
		require.NoError(t, os.WriteFile(folder, []byte("file"), 0600))
		storage := retriable.NewStorage(folder)

		location, err := storage.SaveAuthToken("secret")
		assert.EqualError(t, err, "credentials folder is not a directory: "+folder)
		assert.Equal(t, filepath.Join(folder, tokenFile), location)

		location, err = storage.SaveKey(key)
		assert.EqualError(t, err, "credentials folder is not a directory: "+folder)
		assert.Empty(t, location)
	})

	t.Run("parent_is_file", func(t *testing.T) {
		t.Parallel()
		parent := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(parent, []byte("file"), 0600))
		folder := filepath.Join(parent, "creds")

		_, err := retriable.NewStorage(folder).SaveAuthToken("secret")
		assert.EqualError(t, err, "unable to inspect credentials folder "+folder+": stat "+folder+": not a directory")
	})
}

func TestStorageFolderPermissionErrors(t *testing.T) {
	t.Parallel()
	skipIfRoot(t)

	readOnly := filepath.Join(t.TempDir(), "ro")
	require.NoError(t, os.Mkdir(readOnly, 0500))
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0700) })

	key, err := dpop.GenerateKey("")
	require.NoError(t, err)

	t.Run("parent", func(t *testing.T) {
		t.Parallel()
		folder := filepath.Join(readOnly, "missing", "creds")
		_, err := retriable.NewStorage(folder).SaveAuthToken("secret")
		assert.EqualError(t, err, "unable to create credentials folder parent "+folder+
			": mkdir "+filepath.Join(readOnly, "missing")+": permission denied")
		assert.ErrorIs(t, err, os.ErrPermission)
	})

	t.Run("folder", func(t *testing.T) {
		t.Parallel()
		folder := filepath.Join(readOnly, "creds")
		_, err := retriable.NewStorage(folder).SaveKey(key)
		assert.EqualError(t, err, "unable to create credentials folder "+folder+": mkdir "+folder+": permission denied")
		assert.ErrorIs(t, err, os.ErrPermission)
	})

	t.Run("not_writable", func(t *testing.T) {
		t.Parallel()
		storage := retriable.NewStorage(readOnly)

		_, err := storage.SaveAuthToken("secret")
		require.Error(t, err)
		assert.ErrorIs(t, err, os.ErrPermission)
		assert.True(t, strings.HasPrefix(err.Error(),
			"unable to store token: unable to create temporary credential file: open "+filepath.Join(readOnly, ".credential-")), err.Error())

		_, err = storage.SaveKey(key)
		require.Error(t, err)
		assert.ErrorIs(t, err, os.ErrPermission)
		assert.True(t, strings.HasPrefix(err.Error(),
			"unable to store key: unable to create temporary credential file: open "+filepath.Join(readOnly, ".credential-")), err.Error())

		entries, err := os.ReadDir(readOnly)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

func TestStorageFailedReplaceRemovesTemporaryFile(t *testing.T) {
	t.Parallel()

	folder := t.TempDir()
	// a non-empty directory where the token file belongs cannot be replaced
	location := filepath.Join(folder, tokenFile)
	require.NoError(t, os.Mkdir(location, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(location, "keep"), []byte("keep"), 0600))

	file, err := retriable.NewStorage(folder).SaveAuthToken("secret")
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "unable to store token: unable to replace credential file: rename "), err.Error())
	assert.Equal(t, location, file)

	entries, err := os.ReadDir(folder)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the temporary credential file is removed")
	assert.Equal(t, tokenFile, entries[0].Name())
	assert.True(t, entries[0].IsDir())
	assert.FileExists(t, filepath.Join(location, "keep"))
}
