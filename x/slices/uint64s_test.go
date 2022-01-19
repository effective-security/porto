package slices

import (
	"reflect"
	"sort"
	"testing"
)

func TestUint64s_Sort(t *testing.T) {
	c := func(src, exp Uint64s) {
		sort.Sort(src)
		if !reflect.DeepEqual(exp, src) {
			t.Errorf("Expecting sorted to be %v, but was %v", exp, src)
		}
	}
	c(Uint64s{5, 15, 6, 22, 1, 1}, Uint64s{1, 1, 5, 6, 15, 22})
	c(Uint64s{5}, Uint64s{5})
	c(Uint64s{}, Uint64s{})
	c(Uint64s{5, 5, 1, 1}, Uint64s{1, 1, 5, 5})
}
