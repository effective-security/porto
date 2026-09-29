package tasks

import (
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testTask() {
	logger.Info("TEST: running task.")
}

func taskWithParams(a int, b string) {
	logger.KV(xlog.INFO, "TEST", "running task with parameters:", "a", a, "b", b)
}

type testPublisher struct {
	stopCount int
	runCount  int
	published map[string]Task
	lock      sync.RWMutex
}

func (p *testPublisher) Publish(task Task) {
	p.lock.Lock()
	defer p.lock.Unlock()

	logger.KV(xlog.INFO, "PUBLISHED", task.Name())

	if nil == p.published {
		p.published = make(map[string]Task)
	}
	p.published[task.ID()] = task

	if task.IsRunning() {
		p.runCount++
	} else {
		p.stopCount++
	}
}

func (p *testPublisher) snapshot() (map[string]Task, int, int) {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return maps.Clone(p.published), p.runCount, p.stopCount
}

func Test_StartAndStop(t *testing.T) {
	pub := &testPublisher{}
	scheduler := NewScheduler(WithTickerInterval(time.Millisecond)).(*scheduler)
	require.NotNil(t, scheduler)
	defer scheduler.Stop()

	first := NewTaskAtIntervals(0, Seconds).Do("first", func() {})
	second := NewTaskAtIntervals(0, Seconds).Do("second", func() {})
	scheduler.Add(first)
	scheduler.Add(second)
	assert.Equal(t, 2, scheduler.Count())

	published, _, _ := pub.snapshot()
	assert.Empty(t, published)
	scheduler.SetPublisher(pub)

	err := scheduler.Start()
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, runCount, stopCount := pub.snapshot()
		return first.RunCount() >= 3 && second.RunCount() >= 3 && runCount >= 6 && stopCount >= 6
	}, 5*time.Second, 5*time.Millisecond)

	err = scheduler.Stop()
	require.NoError(t, err)
	assert.False(t, scheduler.IsRunning())
	require.Eventually(t, func() bool {
		return !first.IsRunning() && !second.IsRunning()
	}, time.Second, time.Millisecond)
	published, runCount, stopCount := pub.snapshot()

	tasks := scheduler.List()
	assert.Equal(t, 2, len(tasks))
	for _, j := range tasks {
		assert.False(t, j.IsRunning())
		count := j.RunCount()
		assert.GreaterOrEqual(t, count, uint32(3), "Expected count >= 3, actual %d, name: %s", count, j.Name())
		assert.NotNil(t, published[j.ID()])
	}
	assert.GreaterOrEqual(t, runCount, 6)
	assert.GreaterOrEqual(t, stopCount, 6)

	assert.False(t, scheduler.IsRunning())
}

// Test_StopStartsNoRun checks that no task run starts after Stop returned
// and that runs started before Stop are visible to IsRunning immediately,
// across many start/stop cycles with a fast ticker (formerly P-081).
func Test_StopStartsNoRun(t *testing.T) {
	t.Parallel()
	const interval = time.Millisecond
	const cycles = 25

	scheduler := NewScheduler(WithTickerInterval(interval)).(*scheduler)
	tasks := []Task{
		NewTaskAtIntervals(0, Seconds).Do("first", func() {}),
		NewTaskAtIntervals(0, Seconds).Do("second", func() {}),
	}
	for _, task := range tasks {
		scheduler.Add(task)
	}
	counts := func() []uint32 {
		out := make([]uint32, len(tasks))
		for i, task := range tasks {
			out[i] = task.RunCount()
		}
		return out
	}
	idle := func() bool {
		for _, task := range tasks {
			if task.IsRunning() {
				return false
			}
		}
		return true
	}

	for range cycles {
		before := counts()
		require.NoError(t, scheduler.Start())
		require.Eventually(t, func() bool {
			after := counts()
			for i := range tasks {
				if after[i] <= before[i] {
					return false
				}
			}
			return true
		}, 5*time.Second, interval)

		require.NoError(t, scheduler.Stop())
		require.Eventually(t, idle, time.Second, 100*time.Microsecond)
		stopped := counts()

		// several ticks later nothing has started
		time.Sleep(10 * interval)
		assert.True(t, idle(), "a task is running after Stop")
		assert.Equal(t, stopped, counts(), "a task run started after Stop")
	}
}

func Test_AddAndClear(t *testing.T) {
	scheduler := NewScheduler().(*scheduler)
	require.NotNil(t, scheduler)
	assert.Equal(t, 0, scheduler.Count())
	defer scheduler.Stop()

	scheduler.Add(NewTaskAtIntervals(1, Seconds).Do("test", testTask))
	scheduler.Add(NewTaskAtIntervals(1, Seconds).Do("test", taskWithParams, 1, "hello"))
	assert.Equal(t, 2, scheduler.Count())

	scheduler.Clear()
	assert.Equal(t, 0, scheduler.Count())
}

func Test_AddAndGet(t *testing.T) {
	scheduler := NewScheduler().(*scheduler)
	require.NotNil(t, scheduler)
	assert.Equal(t, 0, scheduler.Count())
	defer scheduler.Stop()

	t1, err := NewTask("every 5 hours", WithID("test1"))
	require.NoError(t, err)
	require.Equal(t, "test1", t1.ID())

	t2, err := NewTask("every 5 hours", WithID("test2"))
	require.NoError(t, err)
	require.Equal(t, "test2", t2.ID())

	scheduler.Add(t1)
	scheduler.Add(t2)
	assert.Equal(t, 2, scheduler.Count())

	t11 := scheduler.Get(t1.ID())
	require.NotNil(t, t11)
	require.Equal(t, t1, t11)

	t12 := scheduler.Get(t2.ID())
	require.NotNil(t, t12)
	require.Equal(t, t2, t12)

	t13 := scheduler.Get("test3")
	require.Nil(t, t13)

	scheduler.Clear()
	assert.Equal(t, 0, scheduler.Count())
}
