package slices

// Uint64s is a slice of uint64, that knows how to be sorted, using sort.Sort
type Uint64s []uint64

// Len returns the length of the slice, as required by sort.Interface
func (a Uint64s) Len() int {
	return len(a)
}

// Less returns the true if the value at index i is smaller than the value at index j, as required by sort.Interface
func (a Uint64s) Less(i, j int) bool {
	return a[i] < a[j]
}

// Swap swaps the values at the indicated indexes, as required by sort.Interface
func (a Uint64s) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
