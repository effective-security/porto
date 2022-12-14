package xdb_test

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/effective-security/porto/x/xdb"
	"github.com/effective-security/xlog"
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
		val    xdb.Time
		exp    time.Time
		isZero bool
		str    string
	}{
		{val: xdb.Time{}, exp: time.Time{}, isZero: true, str: ""},
		{val: xdb.Time(nb), exp: nb, isZero: false, str: "2022-04-01T16:11:15Z"},
		{val: xdb.Time(nbl), exp: nb, isZero: false, str: "2022-04-01T16:11:15Z"},
	}

	for _, tc := range tcases {
		dr, err := tc.val.Value()
		require.NoError(t, err)

		var drv time.Time
		if v, ok := dr.(time.Time); ok {
			drv = v
		}
		assert.Equal(t, tc.exp, drv)

		if tc.isZero {
			assert.True(t, tc.val.IsZero())
			assert.Nil(t, tc.val.Ptr())
		} else {
			assert.False(t, tc.val.IsZero())
			assert.NotNil(t, tc.val.Ptr())
		}
		assert.Equal(t, tc.str, tc.val.String())

		var val2 xdb.Time
		err = val2.Scan(dr)
		require.NoError(t, err)
		assert.EqualValues(t, tc.val.UTC(), val2)
	}

	now := time.Now()
	xnow := xdb.Now()
	xafter := xdb.FromNow(time.Hour)
	assert.Equal(t, xnow.UTC().Unix(), now.Unix())

	now = now.Add(time.Hour)
	now2 := xnow.Add(time.Hour)
	assert.Equal(t, now.Unix(), now2.UTC().Unix())
	assert.Equal(t, xafter.UTC().Unix(), now2.UTC().Unix())

	assert.Equal(t, `"2022-04-01T16:11:15Z"`, xlog.EscapedString(xdb.Time(nbl)))
	assert.Equal(t, `""`, xlog.EscapedString(xdb.Time{}))

	b, err := json.Marshal(xnow)
	require.NoError(t, err)
	var xnow2 xdb.Time
	require.NoError(t, json.Unmarshal(b, &xnow2))
	assert.Equal(t, xnow, xnow2)
}

func TestDbNameFromConnection(t *testing.T) {
	assert.Equal(t, "scannerdb", xdb.DbNameFromConnection("host=localhost port=45432 user=postgres p=xxx sslmode=disable dbname=scannerdb"))
}

func TestNULLString(t *testing.T) {
	tcases := []struct {
		val xdb.NULLString
		exp string
	}{
		{val: "one", exp: "one"},
		{val: "", exp: ""},
	}

	for _, tc := range tcases {
		val := tc.val
		dr, err := val.Value()
		require.NoError(t, err)

		var drv string
		if v, ok := dr.(string); ok {
			drv = v
		}
		assert.Equal(t, tc.exp, drv)

		var val2 xdb.NULLString
		err = val2.Scan(dr)
		require.NoError(t, err)
		assert.EqualValues(t, val, val2)
	}
}
