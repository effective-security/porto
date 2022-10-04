package xdb_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/effective-security/porto/x/xdb"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNullTime(t *testing.T) {
	v := xdb.NullTime(nil)
	require.NotNil(t, v)
	assert.False(t, v.Valid)

	i := time.Now()
	v = xdb.NullTime(&i)
	require.NotNil(t, v)
	assert.True(t, v.Valid)
	assert.Equal(t, i, v.Time)
}

func TestString(t *testing.T) {
	v := xdb.String(nil)
	assert.Empty(t, v)

	s := "1234"
	v = xdb.String(&s)
	assert.Equal(t, s, v)
}

func TestID(t *testing.T) {
	_, err := xdb.ID("")
	require.Error(t, err)

	_, err = xdb.ID("@123")
	require.Error(t, err)

	v, err := xdb.ID("1234567")
	require.NoError(t, err)
	assert.Equal(t, uint64(1234567), v)
}

func TestIDString(t *testing.T) {
	assert.Equal(t, "0", xdb.IDString(0))
	assert.Equal(t, "999", xdb.IDString(999))
}

func TestIsNotFoundError(t *testing.T) {
	assert.True(t, xdb.IsNotFoundError(sql.ErrNoRows))
	assert.True(t, xdb.IsNotFoundError(errors.WithMessage(errors.New("sql: no rows in result set"), "failed")))
}

type validator struct {
	valid bool
}

func (t validator) Validate() error {
	if !t.valid {
		return errors.New("invalid")
	}
	return nil
}

func TestValidate(t *testing.T) {
	assert.Error(t, xdb.Validate(validator{false}))
	assert.NoError(t, xdb.Validate(validator{true}))
	assert.NoError(t, xdb.Validate(nil))
}

func TestIsError(t *testing.T) {
	assert.False(t, xdb.IsNotFoundError(nil))
	assert.False(t, xdb.IsInvalidModel(nil))
}

func TestTimePtr(t *testing.T) {
	var zero xdb.Time
	assert.Nil(t, xdb.TimePtr(zero))
	assert.NotNil(t, xdb.TimePtr(xdb.Time(time.Now())))
}

func TestStrings(t *testing.T) {
	tcases := []struct {
		val []string
		exp string
	}{
		{val: []string{"one", "two"}, exp: "[\"one\",\"two\"]"},
		{val: []string{}, exp: "[]"},
		{val: nil, exp: ""},
	}

	for _, tc := range tcases {
		val := xdb.Strings(tc.val)
		dr, err := val.Value()
		require.NoError(t, err)

		var drv string
		if v, ok := dr.(string); ok {
			drv = v
		}
		assert.Equal(t, tc.exp, drv)

		var val2 xdb.Strings
		err = val2.Scan(dr)
		require.NoError(t, err)
		assert.EqualValues(t, val, val2)
	}
}

func TestMetadata(t *testing.T) {
	tcases := []struct {
		val xdb.Metadata
		exp string
	}{
		{val: xdb.Metadata{"one": "two"}, exp: "{\"one\":\"two\"}"},
		{val: xdb.Metadata{}, exp: ""},
		{val: nil, exp: ""},
	}

	for _, tc := range tcases {
		dr, err := tc.val.Value()
		require.NoError(t, err)

		var drv string
		if v, ok := dr.(string); ok {
			drv = v
		}
		assert.Equal(t, tc.exp, drv)

		var val2 xdb.Metadata
		err = val2.Scan(dr)
		require.NoError(t, err)
		assert.Equal(t, len(tc.val), len(val2))
	}
}

func TestDbTime(t *testing.T) {
	nb, err := time.Parse(time.RFC3339, "2022-04-01T16:11:15.182Z")
	require.NoError(t, err)

	nbl := nb.Local()

	tcases := []struct {
		val xdb.Time
		exp time.Time
	}{
		{val: xdb.Time{}, exp: time.Time{}},
		{val: xdb.Time(nb), exp: nb},
		{val: xdb.Time(nbl), exp: nb},
	}

	for _, tc := range tcases {
		dr, err := tc.val.Value()
		require.NoError(t, err)

		var drv time.Time
		if v, ok := dr.(time.Time); ok {
			drv = v
		}
		assert.Equal(t, tc.exp, drv)

		var val2 xdb.Time
		err = val2.Scan(dr)
		require.NoError(t, err)
		assert.EqualValues(t, tc.val.UTC(), val2)
	}
}

func TestDbNameFromConnection(t *testing.T) {
	assert.Equal(t, "scannerdb", xdb.DbNameFromConnection("host=localhost port=45432 user=postgres p=xxx sslmode=disable dbname=scannerdb"))
}
