package retriable

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cmp"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/configloader"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt/dpop"
	jose "github.com/go-jose/go-jose/v3"
	"github.com/mitchellh/go-homedir"
)

const (
	authTokenFileName = ".auth_token"
)

// Storage is a folder holding the client's credentials: the access token
// in ".auth_token" (0600) and DPoP private keys in "<thumbprint>.jwk",
// plus arbitrary JSON/YAML documents via Marshal/Unmarshal.
type Storage struct {
	folder string
}

// NewStorage returns a Storage rooted at baseFolder; a leading "~" is
// expanded to the home directory. The folder is created lazily on write.
func NewStorage(baseFolder string) *Storage {
	folder, err := homedir.Expand(baseFolder)
	if err != nil {
		logger.KV(xlog.ERROR, "baseFolder", baseFolder, "err", err.Error())
		// fallback
		folder = baseFolder
	}
	return &Storage{folder: folder}
}

// Clean removes the whole storage folder, including tokens and keys.
// Errors are ignored.
func (c *Storage) Clean() {
	os.RemoveAll(c.folder)
}

// Folder returns the storage folder path.
func (c *Storage) Folder() string {
	return c.folder
}

// Unmarshal decodes the JSON (".json") or YAML file, relative to the
// storage folder, into v.
func (c *Storage) Unmarshal(file string, v any) error {
	return configloader.Unmarshal(filepath.Join(c.folder, file), v)
}

// Marshal encodes v as JSON (".json" suffix) or YAML into file, relative
// to the storage folder. The folder must already exist.
func (c *Storage) Marshal(file string, v any) error {
	return configloader.Marshal(filepath.Join(c.folder, file), v)
}

// SaveAuthToken writes the raw token to the .auth_token file (mode 0600),
// creating the folder if needed, and returns the file location.
// The token can be an opaque string, or form encoded as
// access_token={token}&exp={unix_time}&dpop_jkt={jkt}&token_type={Bearer|DPoP}
// (see ParseAuthToken).
func (c *Storage) SaveAuthToken(token string) (string, error) {
	_ = os.MkdirAll(c.folder, 0755)
	location := filepath.Join(c.folder, authTokenFileName)
	err := os.WriteFile(location, []byte(token), 0600)
	if err != nil {
		return location, errors.WithMessagef(err, "unable to store token")
	}
	return location, nil
}

// LoadKey loads the DPoP private key stored as "<label>.jwk" (label is
// normally the key thumbprint) and returns the key and its file path.
func (c *Storage) LoadKey(label string) (*jose.JSONWebKey, string, error) {
	path := filepath.Join(c.folder, label+".jwk")
	return dpop.LoadKey(path)
}

// SaveKey writes the DPoP private key to "<thumbprint>.jwk" in the storage
// folder (created with mode 0700 if needed) and returns the file path.
func (c *Storage) SaveKey(k *jose.JSONWebKey) (string, error) {
	return dpop.SaveKey(c.folder, k)
}

// LoadAuthToken reads and parses the .auth_token file in the storage
// folder; see the package-level LoadAuthToken.
func (c *Storage) LoadAuthToken() (*AuthToken, string, error) {
	return LoadAuthToken(c.folder)
}

// LoadAuthToken reads and parses the ".auth_token" file in dir.
// It returns the token, the file location (also on error) and an error when
// the file is missing or malformed. Expiry is not checked; use AuthToken.Expired.
func LoadAuthToken(dir string) (*AuthToken, string, error) {
	file := filepath.Join(dir, ".auth_token")
	t, err := os.ReadFile(file)
	if err != nil {
		return nil, file, errors.WithMessage(err, "credentials not found")
	}
	return ParseAuthToken(string(t), file)
}

// AuthToken is a parsed access token as stored in .auth_token or an
// environment variable; see ParseAuthToken.
type AuthToken struct {
	// Raw is the original token string.
	Raw string
	// AccessToken is the value sent in the Authorization header.
	AccessToken string
	// RefreshToken is the optional refresh_token value.
	RefreshToken string
	// TokenType is "Bearer" (default) or "DPoP".
	TokenType string
	// DpopJkt is the thumbprint of the DPoP key bound to the token, if any;
	// it names the "<jkt>.jwk" file in Storage.
	DpopJkt string
	// Expires is the optional expiry time (from exp).
	Expires *time.Time
}

// Expired returns true if expiry is present on the token,
// and is behind the current time
func (t *AuthToken) Expired() bool {
	return t.Expires != nil && t.Expires.Before(time.Now())
}

// ParseAuthToken parses a token string. A value without "=" is an opaque
// Bearer access token; otherwise it is parsed as a query string with the
// keys access_token (or id_token, or token), refresh_token, dpop_jkt and
// exp (unix seconds). location is passed through for the caller's logging.
// Expiry is parsed but not validated.
func ParseAuthToken(rawToken, location string) (*AuthToken, string, error) {
	t := &AuthToken{
		Raw:         rawToken,
		TokenType:   "Bearer",
		AccessToken: rawToken,
	}
	if strings.Contains(rawToken, "=") {
		vals, err := url.ParseQuery(rawToken)
		if err != nil {
			return nil, location, errors.WithMessagef(err, "failed to parse token values")
		}
		t.AccessToken = cmp.Or(getValue(vals, "access_token"),
			getValue(vals, "id_token"),
			getValue(vals, "token"))
		t.RefreshToken = getValue(vals, "refresh_token")
		t.DpopJkt = getValue(vals, "dpop_jkt")

		exp := getValue(vals, "exp")
		if exp != "" {
			ux, err := strconv.ParseInt(exp, 10, 64)
			if err != nil {
				return nil, location, errors.WithMessagef(err, "invalid exp value")
			}
			expires := time.Unix(ux, 0)
			t.Expires = &expires
		}
	}

	return t, location, nil
}

// ListKeys returns the DPoP keys found in the storage folder (walked
// recursively, "*.jwk" files). Unreadable or unsupported keys are skipped
// and a missing folder yields an empty list; the error is always nil.
func (c *Storage) ListKeys() ([]*KeyInfo, error) {
	list := []*KeyInfo{}

	// load from the folder
	err := filepath.Walk(c.folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.KV(xlog.DEBUG, "path", path, "err", err.Error())
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".jwk") {
			logger.KV(xlog.DEBUG, "skip", path)
			return nil
		}

		b, err := os.ReadFile(path)
		if err != nil {
			logger.KV(xlog.DEBUG, "skip", path, "err", err.Error())
			return nil
		}
		k := new(jose.JSONWebKey)
		err = json.Unmarshal(b, k)
		if err != nil {
			logger.KV(xlog.DEBUG, "skip", path, "err", err.Error())
			return nil
		}

		ki, err := NewKeyInfo(k)
		if err != nil {
			logger.KV(xlog.DEBUG, "skip", path, "err", err.Error())
			return nil
		}
		list = append(list, ki)
		return nil
	})
	if err != nil {
		logger.KV(xlog.DEBUG, "folder", c.folder, "err", err.Error())
		//return nil, err
	}

	return list, nil
}

// KeyInfo describes a stored DPoP private key.
type KeyInfo struct {
	// KeySize is the modulus size (RSA) or curve size (ECDSA) in bits.
	KeySize int
	// Type is "RSA" or "ECDSA".
	Type string
	// Algo is the JWS algorithm matched to the key size: RS256/384/512 or ES256/384/512.
	Algo string
	// Thumbprint is the base64url SHA-256 JWK thumbprint (the dpop_jkt value).
	Thumbprint string
	// Key is the parsed JWK.
	Key *jose.JSONWebKey
}

// NewKeyInfo computes KeyInfo for an RSA or ECDSA private JWK;
// other key types return an error.
func NewKeyInfo(k *jose.JSONWebKey) (*KeyInfo, error) {
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	si := &KeyInfo{
		Key:        k,
		Thumbprint: base64.RawURLEncoding.EncodeToString(tp),
	}

	switch typ := k.Key.(type) {
	case *rsa.PrivateKey:
		si.KeySize = typ.N.BitLen()
		si.Type = "RSA"
		switch {
		case si.KeySize >= 4096:
			si.Algo = "RS512"
		case si.KeySize >= 3072:
			si.Algo = "RS384"
		default:
			si.Algo = "RS256"
		}
	case *ecdsa.PrivateKey:
		si.Type = "ECDSA"
		switch typ.Curve {
		case elliptic.P521():
			si.Algo = "ES512"
		case elliptic.P384():
			si.Algo = "ES384"
		default:
			si.Algo = "ES256"
		}
		si.KeySize = typ.Curve.Params().BitSize
	default:
		return nil, errors.Errorf("key not supported: %T", typ)
	}
	return si, nil
}
