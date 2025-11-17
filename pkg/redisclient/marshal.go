package redisclient

import (
	"encoding/json"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"
)

// Marshal marshals the value into a format suitable for Redis storage.
// string and []byte are stored as-is, while other types are marshaled to JSON.
func Marshal(v any) (any, error) {
	var value any
	switch t := v.(type) {
	case string:
		value = t
	case []byte:
		value = t
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", errors.Wrapf(err, "failed to marshal value")
		}
		value = string(b)
	}
	return value, nil
}

// UnmarshalStringCmd unmarshals the value from Redis storage into the provided variable.
// string and []byte are converted as-is, while JSON is unmarshaled into the target type.
func UnmarshalStringCmd(val *redis.StringCmd, v any) error {
	switch t := v.(type) {
	case *string:
		*t = val.Val()
	case *[]byte:
		b, err := val.Bytes()
		if err != nil {
			return errors.Wrapf(err, "failed to get key")
		}
		*t = b
	default:
		b, err := val.Bytes()
		if err != nil {
			return errors.Wrapf(err, "failed to get key")
		}
		err = json.Unmarshal(b, v)
		if err != nil {
			return errors.Wrapf(err, "failed to unmarshal value")
		}
	}
	return nil
}
