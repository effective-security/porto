package jwt_test

import (
	"testing"
	"time"

	"github.com/effective-security/porto/pkg/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Config(t *testing.T) {
	_, err := jwt.LoadConfig("testdata/missing.json")
	require.Error(t, err)
	assert.Equal(t, "open testdata/missing.json: no such file or directory", err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_corrupted.1.json")
	require.Error(t, err)
	assert.Equal(t, `unable to unmarshal JSON: "testdata/jwtprov_corrupted.1.json": invalid character 'v' looking for beginning of value`, err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_corrupted.yaml")
	require.Error(t, err)
	assert.Equal(t, `unable to unmarshal YAML: "testdata/jwtprov_corrupted.yaml": yaml: line 3: did not find expected alphabetic or numeric character`, err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_corrupted.2.json")
	require.Error(t, err)
	assert.Equal(t, `missing kid: "testdata/jwtprov_corrupted.2.json"`, err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_no_kid.json")
	require.Error(t, err)
	assert.Equal(t, `missing kid: "testdata/jwtprov_no_kid.json"`, err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_no_keys.json")
	require.Error(t, err)
	assert.Equal(t, `missing keys: "testdata/jwtprov_no_keys.json"`, err.Error())

	cfg, err := jwt.LoadConfig("testdata/jwtprov.json")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 2, len(cfg.Keys))
	assert.Equal(t, "1", cfg.KeyID)
	assert.Equal(t, "trusty.com", cfg.Issuer)
	//assert.Equal(t, jwtprov.trustyClient, cfg.DefaultRole)
	//assert.Equal(t, 2, len(cfg.RolesMap[jwtprov.trustyAdmin]))
}

func Test_Load(t *testing.T) {
	_, err := jwt.Load("testdata/missing.json")
	require.Error(t, err)
	assert.Equal(t, "open testdata/missing.json: no such file or directory", err.Error())

	_, err = jwt.Load("testdata/jwtprov_corrupted.1.json")
	require.Error(t, err)

	_, err = jwt.Load("testdata/jwtprov_corrupted.2.json")
	require.Error(t, err)

	_, err = jwt.Load("testdata/jwtprov.json")
	require.NoError(t, err)

	_, err = jwt.Load("testdata/jwtprov.yaml")
	require.NoError(t, err)

	assert.Panics(t, func() {
		jwt.Load("")
	})
	assert.Panics(t, func() {
		jwt.New(&jwt.Config{
			Issuer: "issuer",
		})
	})
}

func Test_Sign(t *testing.T) {
	p, err := jwt.Load("testdata/jwtprov.json")
	require.NoError(t, err)
	p1, err := jwt.Load("testdata/jwtprov.1.json")
	require.NoError(t, err)
	p2, err := jwt.Load("testdata/jwtprov.2.json")
	require.NoError(t, err)

	token, std, err := p.SignToken("1000", "denis@ekspand.com", "trusty.com", time.Minute)
	require.NoError(t, err)

	claims, err := p.ParseToken(token, "trusty.com")
	require.NoError(t, err)

	assert.Equal(t, *std, *claims)

	_, err = p2.ParseToken(token, "trusty.com")
	require.Error(t, err)
	assert.Equal(t, "failed to verify token: signature is invalid", err.Error())

	_, err = p1.ParseToken(token, "trusty.com")
	require.Error(t, err)
	assert.Equal(t, "invalid issuer: trusty.com", err.Error())
}
