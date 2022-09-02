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

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/x", "xdb")

// Postgres performs the postgres db migration
func Postgres(dbName, migrationsDir string, forceVersion, migrateVersion int, db *sql.DB) error {
	logger.KV(xlog.INFO,
		"db", dbName,
		"status", "load",
		"directory", migrationsDir,
		"forceVersion", forceVersion,
		"migrateVersion", migrateVersion,
	)
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
	m.Log = migrateLog{}

	version, _, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return errors.WithStack(err)
	}
	if err == migrate.ErrNilVersion {
		logger.KV(xlog.INFO, "db", dbName, "reason", "initial_state", "version", "nil")
	} else {
		logger.KV(xlog.INFO, "db", dbName, "reason", "initial_state", "version", version)
	}

	if forceVersion > 0 {
		logger.KV(xlog.NOTICE, "db", dbName, "forceVersion", forceVersion)
		err = m.Force(forceVersion)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	if migrateVersion > 0 {
		logger.KV(xlog.NOTICE, "db", dbName, "migrateVersion", migrateVersion)
		err = m.Migrate(uint(migrateVersion))
	} else {
		err = m.Up()
	}

	if err != nil {
		if strings.Contains(err.Error(), "no change") {
			logger.KV(xlog.INFO, "db", dbName, "status", "no_change", "version", version)
			return nil
		}
		return errors.WithStack(err)
	}

	version, _, err = m.Version()
	if err != nil {
		return errors.WithStack(err)
	}

	logger.KV(xlog.NOTICE, "db", dbName, "status", "changed_state", "version", version)

	return nil
}

type migrateLog struct{}

func (migrateLog) Verbose() bool { return true }
func (migrateLog) Printf(format string, v ...interface{}) {
	logger.Debugf(format, v...)
}
