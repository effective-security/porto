package flake

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	sf        *Flake
	startTime int64
	machineID uint64
)

func init() {
	var st Settings
	st.StartTime = time.Now()

	sf = NewIDGenerator(st).(*Flake)

	startTime = toFlakeTime(st.StartTime)
	machineID = uint64(sf.machineID)
}

func TestFlakeOnce(t *testing.T) {
	assert.Equal(t, int64(1e6), FlakeTimeUnit)

	sleepTime := uint64(5 * FlakeTimeUnit / int64(time.Millisecond))
	time.Sleep(time.Duration(sleepTime) * time.Duration(FlakeTimeUnit))

	id := sf.NextID()
	parts := Decompose(id)
	t.Logf("parts: %+v", parts)

	actualMSB := parts["msb"]
	assert.Equal(t, uint64(0), actualMSB)

	actualTime := parts["time"]
	if actualTime < sleepTime || actualTime > sleepTime+2 {
		t.Errorf("unexpected time: %d", actualTime)
	}

	actualSequence := parts["sequence"]
	assert.Equal(t, uint64(0), actualSequence)

	actualMachineID := parts["machine-id"]
	assert.Equal(t, uint64(machineID), uint64(actualMachineID))
}

func currentTime() int64 {
	return toFlakeTime(time.Now())
}

func TestFlakeFor10Sec(t *testing.T) {
	var numID uint32
	var lastID uint64
	var maxSequence uint64

	initial := currentTime()
	current := initial
	const maxTime = 10 * int64(time.Second) / FlakeTimeUnit
	for current-initial < maxTime {
		id := sf.NextID()
		parts := Decompose(id)
		numID++

		require.Greater(t, id, lastID, "duplicated id")
		lastID = id

		current = currentTime()

		actualMSB := parts["msb"]
		require.Equal(t, uint64(0), actualMSB)

		actualTime := int64(parts["time"])
		overtime := startTime + actualTime - current
		require.LessOrEqual(t, overtime, int64(2), "unexpected overtime", overtime)

		actualSequence := parts["sequence"]
		if maxSequence < actualSequence {
			maxSequence = actualSequence
		}

		actualMachineID := parts["machine-id"]
		require.Equal(t, uint64(machineID), uint64(actualMachineID))
	}

	assert.GreaterOrEqualf(t, maxSequence, uint64(1<<BitLenSequence-1), "unexpected max sequence", maxSequence)

	t.Logf("max sequence: %d", maxSequence)
	t.Logf("max sequence from sf: %d", sf.maxSequence)
	t.Logf("number of id: %d", numID)
}

func TestFlakeInParallel(t *testing.T) {
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	t.Logf("number of cpu: %d", numCPU)

	consumer := make(chan uint64)

	const numID = int(MaskSequence16) * 2
	generate := func() {
		for i := 0; i < numID; i++ {
			consumer <- sf.NextID()
		}
	}

	const numGenerator = 10
	for i := 0; i < numGenerator; i++ {
		go generate()
	}

	var maxSequence uint64

	set := mapset.NewSet()
	for i := 0; i < numID*numGenerator; i++ {
		id := <-consumer
		if set.Contains(id) {
			t.Fatal("duplicated id")
		} else {
			set.Add(id)
		}

		parts := Decompose(id)

		actualSequence := parts["sequence"]
		if maxSequence < actualSequence {
			maxSequence = actualSequence
		}
	}
	t.Logf("number of id: %d", set.Cardinality())
	t.Logf("max sequence: %d", maxSequence)
}

func TestIdGenerator(t *testing.T) {
	set := mapset.NewSet()

	const maxRoutines = 50
	const maxIds = int(MaskSequence16) * 10

	totalCount := uint64(0)
	useCode := func(code uint64) error {
		atomic.AddUint64(&totalCount, 1)
		if set.Contains(code) {
			t.Fatal("duplicated id")
		} else {
			set.Add(code)
		}
		return nil
	}

	var wg sync.WaitGroup

	for i := 0; i < maxRoutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for c := 0; c < maxIds; c++ {
				id := DefaultIDGenerator.NextID()
				err := useCode(id)
				assert.NoError(t, err)
				if err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()

	dsf := DefaultIDGenerator.(*Flake)
	t.Logf("number of id: %d", set.Cardinality())
	t.Logf("max id per go: %d", maxIds)
	t.Logf("max sequence: %d", dsf.maxSequence)

	assert.GreaterOrEqual(t, int(dsf.maxSequence), int(MaskSequence16))
	assert.Equal(t, uint64(maxRoutines*maxIds), totalCount)
}

func TestNilFlake(t *testing.T) {
	var startInFuture Settings
	startInFuture.StartTime = time.Now().Add(time.Duration(1) * time.Minute)
	assert.Panics(t, func() {
		NewIDGenerator(startInFuture)
	})

	var noMachineID Settings
	noMachineID.MachineID = func() (uint16, error) {
		return 0, fmt.Errorf("no machine id")
	}

	assert.Panics(t, func() {
		NewIDGenerator(noMachineID)
	})

	var invalidMachineID Settings
	invalidMachineID.CheckMachineID = func(uint16) bool {
		return false
	}
	assert.Panics(t, func() {
		NewIDGenerator(invalidMachineID)
	})
}

func pseudoSleep(period time.Duration) {
	sf.startTime -= int64(period) / FlakeTimeUnit
}

func TestNextIDError(t *testing.T) {
	year := time.Duration(365*24) * time.Hour

	for i := 1; i < 70; i++ {
		t.Logf("over %d year", i)
		pseudoSleep(year)
		sf.NextID()
	}

	pseudoSleep(time.Duration(1) * year)
	assert.Panics(t, func() {
		sf.NextID()
	})
}
