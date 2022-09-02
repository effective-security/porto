package migrate_test

import (
	"database/sql"
	"testing"

	"github.com/effective-security/porto/x/xdb/migrate"
	"github.com/stretchr/testify/assert"
)

func TestPostgres(t *testing.T) {
	err := migrate.Postgres("test", "", 1, 1, nil)
	assert.NoError(t, err)

	assert.Panics(t, func() {
		migrate.Postgres("test", "testdata", 1, 1, &sql.DB{})
	})
}
