package xdb

import (
	"database/sql/driver"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// ID defines a type to convert between internal uint64 and external string representations of ID
type ID struct {
	id  uint64
	val string
}

// NewID returns ID
func NewID(id uint64) ID {
	return ID{id: id}
}

// MustID returns ID or panics if the value is invalid
func MustID(val string) ID {
	var id ID
	if err := id.Set(val); err != nil {
		panic(err)
	}
	return id
}

// ParseID returns ID or empty if val is not valid ID
func ParseID(val string) ID {
	var id ID
	_ = id.Set(val)
	return id
}

// MarshalJSON implements json.Marshaler interface
func (v ID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%d", v.id)), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// The time is expected to be a quoted string in RFC 3339 format.
func (v *ID) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), "\"")
	if s == "" || s == "0" {
		*v = ID{id: 0, val: ""}
		return nil
	}

	f, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return errors.Errorf("expected number value to unmarshal ID: %s", s)
	}
	*v = ID{id: f, val: s}
	return nil
}

func (v ID) String() string {
	if v.val == "" && v.id != 0 {
		v.val = IDString(v.id)
	}
	return v.val
}

// UInt64 returns uint64 value
func (v ID) UInt64() uint64 {
	return v.id
}

// Set the value
func (v *ID) Set(val string) error {
	id, err := ParseUint(val)
	if err != nil || id == 0 {
		return errors.Errorf("invalid ID")
	}
	v.id = id
	v.val = val

	return nil
}

// Scan implements the Scanner interface.
func (v *ID) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	var id uint64
	switch vid := value.(type) {
	case uint64:
		id = vid
	case int64:
		id = uint64(vid)
	case int:
		id = uint64(vid)
	case uint:
		id = uint64(vid)
	default:
		return errors.Errorf("unsupported scan type: %T", value)
	}

	*v = ID{
		id: id,
	}
	return nil
}

// Value implements the driver Valuer interface.
func (v ID) Value() (driver.Value, error) {
	// driver.Value support only int64
	return int64(v.id), nil
}
