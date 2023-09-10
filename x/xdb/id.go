package xdb

import (
	"database/sql/driver"
	"fmt"
	"strconv"
	"strings"

	"github.com/effective-security/porto/xhttp/httperror"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
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

// Invalid returns if ID is invalid
func (v ID) Invalid() bool {
	return v.id == 0
}

// IsZero returns if ID is 0
func (v ID) IsZero() bool {
	return v.id == 0
}

// Valid returns if ID is valid
func (v ID) Valid() bool {
	return v.id != 0
}

// UInt64 returns uint64 value
func (v ID) UInt64() uint64 {
	return v.id
}

// Reset the value
func (v *ID) Reset() {
	v.id = 0
	v.val = ""
}

// Set the value
func (v *ID) Set(val string) error {
	id, err := ParseUint(val)
	if err != nil || id == 0 {
		return httperror.NewGrpc(codes.InvalidArgument, "invalid ID")
	}
	v.id = id
	v.val = val

	return nil
}

// Scan implements the Scanner interface.
func (v *ID) Scan(value any) error {
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
	// this makes sure ID can be used as NULL in SQL
	// however this also means that ID(0) will be treated as NULL
	if v.id == 0 {
		return nil, nil
	}

	// driver.Value support only int64
	return int64(v.id), nil
}

// IDArray defines a list of IDArray
type IDArray []ID

// Scan implements the Scanner interface for IDs
func (n *IDArray) Scan(value any) error {
	*n = nil
	if value == nil {
		return nil
	}

	var int64Array pq.Int64Array
	err := int64Array.Scan(value)
	if err != nil {
		return errors.Wrap(err, "failed to scan IDs")
	}

	count := len(int64Array)
	if count > 0 {
		ids := make([]ID, count)
		for i, id := range int64Array {
			ids[i] = NewID(uint64(id))
		}
		*n = ids
	}

	return nil
}

// Value implements the driver Valuer interface for IDs
func (n IDArray) Value() (driver.Value, error) {
	if len(n) == 0 {
		return nil, nil
	}

	ids := make([]int64, len(n))
	for i, id := range n {
		ids[i] = int64(id.UInt64())
	}

	int64Array, err := pq.Int64Array(ids).Value()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get IDs value")
	}

	return int64Array, nil
}

// Strings returns string representation of IDs
func (n IDArray) Strings() []string {
	var list []string
	for _, id := range n {
		list = append(list, id.String())
	}
	return list
}
