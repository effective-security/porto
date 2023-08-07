package xdb

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Max values, common for strings
const (
	MaxLenForName     = 64
	MaxLenForEmail    = 160
	MaxLenForShortURL = 256
)

// Scanner is DB scan interface
type Scanner interface {
	Scan(dest ...any) error
}

// Validator provides schema validation interface
type Validator interface {
	// Validate returns error if the model is not valid
	Validate() error
}

// Validate returns error if the model is not valid
func Validate(m interface{}) error {
	if v, ok := m.(Validator); ok {
		return v.Validate()
	}
	return nil
}

// NullTime from *time.Time
func NullTime(val *time.Time) sql.NullTime {
	if val == nil {
		return sql.NullTime{Valid: false}
	}

	return sql.NullTime{Time: *val, Valid: true}
}

// TimePtr returns nil if time is zero, or pointer with a value
func TimePtr(val Time) *time.Time {
	t := time.Time(val)
	if t.IsZero() {
		return nil
	}
	return &t
}

// String returns string
func String(val *string) string {
	if val == nil {
		return ""
	}
	return *val
}

// ParseUint returns id from the string
func ParseUint(id string) (uint64, error) {
	i64, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return i64, nil
}

// IDString returns string id
func IDString(id uint64) string {
	return strconv.FormatUint(id, 10)
}

// IsNotFoundError returns true, if error is NotFound
func IsNotFoundError(err error) bool {
	return err != nil &&
		(err == sql.ErrNoRows || strings.Contains(err.Error(), "no rows in result set"))
}

// IsInvalidModel returns true, if error is InvalidModel
func IsInvalidModel(err error) bool {
	return err != nil && strings.Contains(err.Error(), "invalid model")
}

// DbNameFromConnection return DB name from connection
func DbNameFromConnection(conn string) string {
	idx := strings.LastIndex(conn, "dbname=")
	return conn[idx+7:]
}

// SQL provides interface for Db operations
type SQL interface {
	// QueryContext executes a query that returns rows, typically a SELECT.
	// The args are for any placeholder parameters in the query.
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	// QueryRowContext executes a query that is expected to return at most one row.
	// QueryRowContext always returns a non-nil value. Errors are deferred until
	// Row's Scan method is called.
	// If the query selects no rows, the *Row's Scan will return ErrNoRows.
	// Otherwise, the *Row's Scan scans the first selected row and discards
	// the rest.
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	// ExecContext executes a query without returning any rows.
	// The args are for any placeholder parameters in the query.
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}
