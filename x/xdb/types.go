package xdb

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

// Strings de/encodes the string slice to/from a SQL string.
type Strings []string

// Scan implements the Scanner interface.
func (n *Strings) Scan(value interface{}) error {
	if value == nil {
		*n = nil
		return nil
	}
	v := fmt.Sprint(value)
	if len(v) == 0 {
		*n = Strings{}
		return nil
	}
	return errors.WithStack(json.Unmarshal([]byte(v), n))
}

// Value implements the driver Valuer interface.
func (n Strings) Value() (driver.Value, error) {
	if n == nil {
		return nil, nil
	}
	value, err := json.Marshal(n)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return string(value), nil
}

// Metadata de/encodes the string map to/from a SQL string.
type Metadata map[string]string

// Scan implements the Scanner interface.
func (n *Metadata) Scan(value interface{}) error {
	if value == nil {
		*n = nil
		return nil
	}
	v := fmt.Sprint(value)
	if len(v) == 0 {
		*n = Metadata{}
		return nil
	}
	return errors.WithStack(json.Unmarshal([]byte(v), n))
}

// Value implements the driver Valuer interface.
func (n Metadata) Value() (driver.Value, error) {
	if len(n) == 0 {
		return nil, nil
	}
	value, err := json.Marshal(n)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return string(value), nil
}

// NULLString de/encodes the string a SQL string.
type NULLString string

// Scan implements the Scanner interface.
func (ns *NULLString) Scan(value interface{}) error {
	var v sql.NullString
	if err := (&v).Scan(value); err != nil {
		return errors.WithStack(err)
	}
	if v.Valid {
		*ns = NULLString(v.String)
	} else {
		*ns = ""
	}

	return nil
}

// Value implements the driver Valuer interface.
func (ns NULLString) Value() (driver.Value, error) {
	if ns == "" {
		return nil, nil
	}
	return string(ns), nil
}
