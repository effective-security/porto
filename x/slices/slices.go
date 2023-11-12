// Package slices provides additional slice functions on common slice types
package slices

import (
	"strings"
)

// ByteSlicesEqual returns true only if the contents of the 2 slices are the same
func ByteSlicesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, v := range a {
		if v != b[idx] {
			return false
		}
	}
	return true
}

// StringSlicesEqual returns true only if the contents of the 2 slices are the same
func StringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, v := range a {
		if v != b[idx] {
			return false
		}
	}
	return true
}

// ContainsString returns true if the items slice contains a value equal to item
// Note that this can end up traversing the entire slice, and so is only really
// suitable for small slices, for larger data sets, consider using a map instead.
func ContainsString(items []string, item string) bool {
	for _, x := range items {
		if x == item {
			return true
		}
	}
	return false
}

// StringContainsOneOf returns true if one of items slice is a substring of specified value.
func StringContainsOneOf(item string, items []string) bool {
	for _, x := range items {
		if strings.Contains(item, x) {
			return true
		}
	}
	return false
}

// StringStartsWithOneOf returns true if one of items slice is a prefix of specified value.
func StringStartsWithOneOf(value string, items []string) bool {
	for _, x := range items {
		if strings.HasPrefix(value, x) {
			return true
		}
	}
	return false
}

// ContainsStringEqualFold returns true if the items slice contains a value equal to item
// ignoring case [i.e. using EqualFold]
// Note that this can end up traversing the entire slice, and so is only really
// suitable for small slices, for larger data sets, consider using a map instead.
func ContainsStringEqualFold(items []string, item string) bool {
	for _, x := range items {
		if strings.EqualFold(x, item) {
			return true
		}
	}
	return false
}

// CloneStrings will return an independnt copy of the src slice, it preserves
// the distinction between a nil value and an empty slice.
func CloneStrings(src []string) []string {
	if src != nil {
		c := make([]string, len(src))
		copy(c, src)
		return c
	}
	return nil
}

// NvlString returns the first string from the supplied list that has len() > 0
// or "" if all the strings are empty
func NvlString(items ...string) string {
	for _, x := range items {
		if len(x) > 0 {
			return x
		}
	}
	return ""
}

// Prefixed returns a new slice of strings with each input item prefixed by the supplied prefix
// e.g. Prefixed("foo", []string{"bar","bob"}) would return []string{"foobar", "foobob"}
// the input slice is not modified.
func Prefixed(prefix string, items []string) []string {
	return MapStringSlice(items, func(in string) string {
		return prefix + in
	})
}

// Suffixed returns a new slice of strings which each input item suffixed by the supplied suffix
// e.g. Suffixed("foo", []string{"bar","bob"}) would return []string{"barfoo", "bobfoo"}
// the input slice is not modified
func Suffixed(suffix string, items []string) []string {
	return MapStringSlice(items, func(in string) string {
		return in + suffix
	})
}

// Quoted returns a new slice of strings where each input stream has been wrapped in quotes
func Quoted(items []string) []string {
	return MapStringSlice(items, func(in string) string {
		return `"` + in + `"`
	})
}

// MapStringSlice returns a new slices of strings that is the result of applies mapFn
// to each string in the input slice.
func MapStringSlice(items []string, mapFn func(in string) string) []string {
	res := make([]string, len(items))
	for idx, v := range items {
		res[idx] = mapFn(v)
	}
	return res
}

// BoolSlicesEqual returns true only if the contents of the 2 slices are the same
func BoolSlicesEqual(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, v := range a {
		if v != b[idx] {
			return false
		}
	}
	return true
}

// StringsCoalesce returns the first non-empty string value
func StringsCoalesce(str ...string) string {
	for _, s := range str {
		if len(s) > 0 {
			return s
		}
	}
	return ""
}

// StringUpto returns the beginning of the string up to `max`
func StringUpto(str string, max int) string {
	if len(str) > max {
		return str[:max]
	}
	return str
}

// Int64SlicesEqual returns true only if the contents of the 2 slices are the same
func Int64SlicesEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, v := range a {
		if v != b[idx] {
			return false
		}
	}
	return true
}

// Uint64SlicesEqual returns true only if the contents of the 2 slices are the same
func Uint64SlicesEqual(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, v := range a {
		if v != b[idx] {
			return false
		}
	}
	return true
}

// Float64SlicesEqual returns true only if the contents of the 2 slices are the same
func Float64SlicesEqual(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, v := range a {
		if v != b[idx] {
			return false
		}
	}
	return true
}

// UniqueStrings removes duplicates from the given list
func UniqueStrings(dups []string) []string {
	if len(dups) < 2 {
		return dups
	}
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range dups {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// NvlNumber returns the first value from the supplied list that is not 0, or 0 if there are no values that are not zero
func NvlNumber[T ~int | ~int32 | ~uint | ~uint32 | ~int64 | ~uint64](items ...T) T {
	for _, x := range items {
		if x != 0 {
			return x
		}
	}
	return 0
}

// Measurable interface
type Measurable[T any] interface {
	~string | ~[]string | ~[]T
}

// Coalesce returns the first non-empty value
func Coalesce[M Measurable[any]](args ...M) M {
	for _, s := range args {
		if len(s) > 0 {
			return s
		}
	}
	return args[0]
}

// Select returns a if cond is true, otherwise b
func Select[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
