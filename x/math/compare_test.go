package math

import (
	"math"
	"testing"
	"time"
)

func TestMath_Max(t *testing.T) {
	vals := [][]int{
		{0, 0, 0},
		{0, 1, 1},
		{1, 0, 1},
		{42, 0, 42},
		{999999, 999998, 999999},
		{-1, 0, 0},
		{0, -1, 0},
		{1, -1, 1},
	}

	for _, v := range vals {
		r := Max(v[0], v[1])
		if r != v[2] {
			t.Errorf("Max(%v,%v) returned %v, expecting %v", v[0], v[1], r, v[2])
		}
	}
}

func TestMath_Min(t *testing.T) {
	vals := [][]int{
		{0, 0, 0},
		{0, 1, 0},
		{1, 0, 0},
		{42, 0, 0},
		{999999, 999998, 999998},
		{-1, 0, -1},
		{0, -1, -1},
		{1, -1, -1},
	}

	for _, v := range vals {
		r := Min(v[0], v[1])
		if r != v[2] {
			t.Errorf("Min(%v,%v) returned %v, expecting %v", v[0], v[1], r, v[2])
		}
	}
}

func TestMath_MaxUint64(t *testing.T) {
	vals := [][]uint64{
		{0, 0, 0},
		{0, 1, 1},
		{1, 0, 1},
		{42, 0, 42},
		{999999, 999998, 999999},
		{math.MaxUint64, 999998, math.MaxUint64},
	}

	for _, v := range vals {
		r := MaxUint64(v[0], v[1])
		if r != v[2] {
			t.Errorf("MaxUint64(%v,%v) returned %v, expecting %v", v[0], v[1], r, v[2])
		}
	}
}

func TestMath_MinUint64(t *testing.T) {
	vals := [][]uint64{
		{0, 0, 0},
		{0, 1, 0},
		{1, 0, 0},
		{42, 0, 0},
		{math.MaxUint64, 999998, 999998},
	}

	for _, v := range vals {
		r := MinUint64(v[0], v[1])
		if r != v[2] {
			t.Errorf("MinUint64(%v,%v) returned %v, expecting %v", v[0], v[1], r, v[2])
		}
	}
}

func TestMath_MinDuration(t *testing.T) {
	vals := [][]time.Duration{
		{time.Second, time.Minute, time.Second},
		{0, 1, 0},
		{time.Minute, time.Second, time.Second},
		{time.Second, time.Second, time.Second},
	}
	for _, v := range vals {
		r := MinDuration(v[0], v[1])
		if r != v[2] {
			t.Errorf("MinDuration(%v,%v) returned %v, expecting %v", v[0], v[1], r, v[2])
		}
	}
}

func TestMath_MaxDuration(t *testing.T) {
	vals := [][]time.Duration{
		{time.Second, time.Minute, time.Minute},
		{0, 1, 1},
		{time.Minute, time.Second, time.Minute},
		{time.Second, time.Second, time.Second},
	}
	for _, v := range vals {
		r := MaxDuration(v[0], v[1])
		if r != v[2] {
			t.Errorf("MaxDuration(%v,%v) returned %v, expecting %v", v[0], v[1], r, v[2])
		}
	}
}
