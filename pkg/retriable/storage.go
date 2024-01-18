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
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/effective-security/x/values"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/jwt/dpop"
	jose "github.com/go-jose/go-jose/v3"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
)

const (
	authTokenFileName = ".auth_token"
)

// Storage provides Client storage
type Storage struct {
	folder           string
	envAuthTokenName string
}

// OpenStorage returns Storage
func OpenStorage(baseFolder, host, envAuthTokenName string) *Storage {
	folder := ExpandFolder(baseFolder)
	if host != "" {
		folder = path.Join(folder, HostFolderName(host))
	}
	return &Storage{folder: folder, envAuthTokenName: envAuthTokenName}
}

// Clean removes all stored files
func (c *Storage) Clean() {
	os.RemoveAll(c.folder)
}

// SaveAuthToken persists auth token
// the token format can be as opaque string, or as form encoded
// access_token={token}&exp={unix_time}&dpop_jkt={jkt}&token_type={Bearer|DPoP}
func (c *Storage) SaveAuthToken(token string) (string, error) {
	_ = os.MkdirAll(c.folder, 0755)
	location := path.Join(c.folder, authTokenFileName)
	err := os.WriteFile(location, []byte(token), 0600)
	if err != nil {
		return location, errors.WithMessagef(err, "unable to store token")
	}
	return location, nil
}

// LoadKey returns *jose.JSONWebKey
func (c *Storage) LoadKey(label string) (*jose.JSONWebKey, string, error) {
	path := path.Join(c.folder, label+".jwk")
	return dpop.LoadKey(path)
}

// SaveKey saves the key to storage
func (c *Storage) SaveKey(k *jose.JSONWebKey) (string, error) {
	return dpop.SaveKey(c.folder, k)
}

// LoadAuthToken returns LoadAuthToken
func (c *Storage) LoadAuthToken() (*AuthToken, string, error) {
	if c.envAuthTokenName != "" {
		val := os.Getenv(c.envAuthTokenName)
		if val != "" {
			return ParseAuthToken(val, "env://"+c.envAuthTokenName)
		}
	}
	return LoadAuthToken(c.folder)
}

// LoadAuthToken loads .auth_token file
func LoadAuthToken(dir string) (*AuthToken, string, error) {
	file := path.Join(dir, ".auth_token")
	t, err := os.ReadFile(file)
	if err != nil {
		return nil, file, errors.WithMessage(err, "credentials not found")
	}
	return ParseAuthToken(string(t), file)
}

// AuthToken provides auth token info
type AuthToken struct {
	Raw          string
	AccessToken  string
	RefreshToken string
	TokenType    string
	DpopJkt      string
	Expires      *time.Time
}

// Expired returns true if expiry is present on the token,
// and is behind the current time
func (t *AuthToken) Expired() bool {
	return t.Expires != nil && t.Expires.Before(time.Now())
}

// ParseAuthToken parses stored token and validates expiration
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
		t.AccessToken = values.StringsCoalesce(getValue(vals, "access_token"),
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

// ExpandFolder returns expanded StorageFolder
func ExpandFolder(dir string) string {
	if dir == "" {
		dirname, _ := os.UserHomeDir()
		// returns default
		dir = path.Join(dirname, ".config", ".retriable")
	}
	dir, _ = homedir.Expand(dir)
	return dir
}

// ListKeys returns list of DPoP keys in the storage
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

// KeyInfo specifies key info
type KeyInfo struct {
	KeySize    int
	Type       string
	Algo       string
	Thumbprint string
	Key        *jose.JSONWebKey
}

// NewKeyInfo returns *keyInfo
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
