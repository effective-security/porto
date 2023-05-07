package xdb

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

// Time implements sql.Time functionality and always returns UTC
type Time time.Time

// Scan implements the Scanner interface.
func (ns *Time) Scan(value interface{}) error {
	var v sql.NullTime
	if err := (&v).Scan(value); err != nil {
		return errors.WithStack(err)
	}
	var zero Time
	if v.Valid {
		zero = Time(v.Time.UTC())
	}
	*ns = zero

	return nil
}

// Value implements the driver Valuer interface.
func (ns Time) Value() (driver.Value, error) {
	nst := time.Time(ns)
	return sql.NullTime{
		Valid: !nst.IsZero(),
		Time:  nst.UTC(),
	}.Value()
}

// Now returns Time in UTC,
// with Second presicions
func Now() Time {
	return Time(time.Now().Truncate(time.Second).UTC())
}

// UTC returns Time in UTC,
func UTC(t time.Time) Time {
	return Time(t.UTC())
}

// FromNow returns Time in UTC after now,
// with Second presicions
func FromNow(after time.Duration) Time {
	return Time(time.Now().Add(after).Truncate(time.Second).UTC())
}

// FromUnixMilli returns Time from Unix milliseconds elapsed since January 1, 1970 UTC.
func FromUnixMilli(tm int64) Time {
	sec := tm / 1000
	msec := tm % 1000
	return Time(time.Unix(sec, msec*int64(time.Millisecond)).UTC())
}

// ParseTime returns Time from RFC3339 format
func ParseTime(val string) Time {
	t, _ := time.Parse(time.RFC3339, val)
	return Time(t.UTC())
}

// UnixMilli returns t as a Unix time, the number of milliseconds elapsed since January 1, 1970 UTC.
func (ns Time) UnixMilli() int64 {
	return time.Time(ns).UnixMilli()
}

// Add returns Time in UTC after this thime,
// with Second presicions
func (ns Time) Add(after time.Duration) Time {
	return Time(time.Time(ns).Add(after).Truncate(time.Second).UTC())
}

// UTC returns t with the location set to UTC.
func (ns Time) UTC() time.Time {
	return time.Time(ns).UTC()
}

// IsZero reports whether t represents the zero time instant, January 1, year 1, 00:00:00 UTC.
func (ns Time) IsZero() bool {
	return time.Time(ns).IsZero()
}

// IsNil reports whether t represents the zero time instant, January 1, year 1, 00:00:00 UTC.
func (ns Time) IsNil() bool {
	return time.Time(ns).IsZero()
}

// Ptr returns pointer to Time, or nil if the time is zero
func (ns Time) Ptr() *time.Time {
	t := ns.UTC()
	if t.IsZero() {
		return nil
	}
	return &t
}

// String returns string in RFC3339 format,
// if it's Zero time, an empty string is returned
func (ns Time) String() string {
	t := ns.UTC()
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// MarshalJSON implements the json.Marshaler interface.
// The time is a quoted string in RFC 3339 format, with sub-second precision added if present.
func (ns Time) MarshalJSON() ([]byte, error) {
	t := time.Time(ns)
	if t.IsZero() {
		return []byte(`""`), nil
	}
	return time.Time(ns).MarshalJSON()
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// The time is expected to be a quoted string in RFC 3339 format.
func (ns *Time) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || bytes.Equal([]byte(`""`), data) {
		*ns = Time{}
		return nil
	}
	return errors.WithStack(json.Unmarshal([]byte(data), (*time.Time)(ns)))
}

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
