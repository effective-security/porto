package retriable

import (
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/effective-security/porto/x/slices"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
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
func OpenStorage(folder, envAuthTokenName string) *Storage {
	return &Storage{folder: ExpandStorageFolder(folder), envAuthTokenName: envAuthTokenName}
}

// Clean removes all stored files
func (c *Storage) Clean() {
	os.RemoveAll(c.folder)
}

// SaveAuthToken persists auth token
// the token format can be as opaque string, or as form encoded
// access_token={token}&exp={unix_time}&dpop_jkt={jkt}&token_type={Bearer|DPoP}
func (c *Storage) SaveAuthToken(token string) error {
	_ = os.MkdirAll(c.folder, 0755)
	err := os.WriteFile(path.Join(c.folder, authTokenFileName), []byte(token), 0600)
	if err != nil {
		return errors.WithMessagef(err, "unable to store token")
	}
	return nil
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
func (c *Storage) LoadAuthToken() (*AuthToken, error) {
	if c.envAuthTokenName != "" {
		val := os.Getenv(c.envAuthTokenName)
		if val != "" {
			return ParseAuthToken(val)
		}
	}
	return LoadAuthToken(c.folder)
}

// LoadAuthToken loads .auth_token file
func LoadAuthToken(dir string) (*AuthToken, error) {
	file := path.Join(dir, ".auth_token")
	t, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.WithMessage(err, "credentials not found")
	}
	return ParseAuthToken(string(t))
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
func ParseAuthToken(rawToken string) (*AuthToken, error) {
	t := &AuthToken{
		Raw:         rawToken,
		TokenType:   "Bearer",
		AccessToken: rawToken,
	}
	if strings.Contains(rawToken, "=") {
		vals, err := url.ParseQuery(rawToken)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse token values")
		}
		t.AccessToken = slices.StringsCoalesce(getValue(vals, "access_token"),
			getValue(vals, "id_token"),
			getValue(vals, "token"))
		t.RefreshToken = getValue(vals, "refresh_token")
		t.DpopJkt = getValue(vals, "dpop_jkt")

		exp := getValue(vals, "exp")
		if exp != "" {
			ux, err := strconv.ParseInt(exp, 10, 64)
			if err != nil {
				return nil, errors.WithMessagef(err, "invalid exp value")
			}
			expires := time.Unix(ux, 0)
			t.Expires = &expires
		}
	}

	return t, nil
}

// ExpandStorageFolder returns expanded StorageFolder
func ExpandStorageFolder(dir string) string {
	if dir == "" {
		dirname, _ := os.UserHomeDir()
		// returns default
		dir = path.Join(dirname, ".config", ".retriable")
	}
	dir, _ = homedir.Expand(dir)
	return dir
}
