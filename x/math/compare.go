// Package math implements basic operations on various types
package math

import (
	"time"
)

// Max returns the larger of the 2 supplied int's
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Min returns the smaller of the 2 supplied int's
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MaxUint64 returns the larger of the 2 supplied uint64's
func MaxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// MinUint64 returns the smaller of the 2 supplied uint64's
func MinUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// MinDuration returns the smaller of teh 2 supplied Durations
func MinDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// MaxDuration returns the larger of the 2 supplied Durations
func MaxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
