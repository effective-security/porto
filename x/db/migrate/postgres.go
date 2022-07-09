package migrate

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/effective-security/xlog"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/pkg/errors"

	// register Postgres driver
	_ "github.com/lib/pq"
	// register file driver for migration
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/x", "db")

// Postgres performs the postgres db migration
func Postgres(dbName, migrationsDir string, forceVersion int, db *sql.DB) error {
	logger.Infof("db=%s, reason=load, directory=%q, forceVersion=%d", dbName, migrationsDir, forceVersion)
	if len(migrationsDir) == 0 {
		return nil
	}

	if _, err := os.Stat(migrationsDir); err != nil {
		return errors.WithMessagef(err, "directory %q inaccessible", migrationsDir)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return errors.WithStack(err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationsDir),
		"postgres",
		driver)
	if err != nil {
		return errors.WithStack(err)
	}

	version, _, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return errors.WithStack(err)
	}
	if err == migrate.ErrNilVersion {
		logger.Infof("db=%s, reason=initial_state, version=nil", dbName)
	} else {
		logger.Infof("db=%s, reason=initial_state, version=%d", dbName, version)
	}

	if forceVersion > 0 {
		logger.Infof("db=%s, forceVersion=%d", dbName, forceVersion)
		err = m.Force(forceVersion)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	err = m.Up()
	if err != nil {
		if strings.Contains(err.Error(), "no change") {
			logger.Infof("db=%s, reason=no_change, version=%d", dbName, version)
			return nil
		}
		return errors.WithStack(err)
	}

	version, _, err = m.Version()
	if err != nil {
		return errors.WithStack(err)
	}

	logger.Infof("db=%s, reason=changed_state, version=%d", dbName, version)

	return nil
}
