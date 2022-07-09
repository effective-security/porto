package db_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/effective-security/porto/x/db"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNullTime(t *testing.T) {
	v := db.NullTime(nil)
	require.NotNil(t, v)
	assert.False(t, v.Valid)

	i := time.Now()
	v = db.NullTime(&i)
	require.NotNil(t, v)
	assert.True(t, v.Valid)
	assert.Equal(t, i, v.Time)
}

func TestString(t *testing.T) {
	v := db.String(nil)
	assert.Empty(t, v)

	s := "1234"
	v = db.String(&s)
	assert.Equal(t, s, v)
}

func TestID(t *testing.T) {
	_, err := db.ID("")
	require.Error(t, err)

	_, err = db.ID("@123")
	require.Error(t, err)

	v, err := db.ID("1234567")
	require.NoError(t, err)
	assert.Equal(t, uint64(1234567), v)
}

func TestIDString(t *testing.T) {
	assert.Equal(t, "0", db.IDString(0))
	assert.Equal(t, "999", db.IDString(999))
}

func TestIsNotFoundError(t *testing.T) {
	assert.True(t, db.IsNotFoundError(sql.ErrNoRows))
	assert.True(t, db.IsNotFoundError(errors.WithMessage(errors.New("sql: no rows in result set"), "failed")))
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
	assert.Error(t, db.Validate(validator{false}))
	assert.NoError(t, db.Validate(validator{true}))
	assert.NoError(t, db.Validate(nil))
}
