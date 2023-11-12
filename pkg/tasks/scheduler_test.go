package tasks

import (
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

func Test_StartAndStop(t *testing.T) {
	// xlog.SetFormatter(xlog.NewPrettyFormatter(os.Stdout))
	// xlog.SetGlobalLogLevel(xlog.DEBUG)

	pub := &testPublisher{}
	scheduler := NewScheduler().(*scheduler)
	require.NotNil(t, scheduler)
	defer scheduler.Stop()

	scheduler.Add(NewTaskAtIntervals(1, Seconds).Do("test", testTask))
	scheduler.Add(NewTaskAtIntervals(1, Seconds).Do("test", taskWithParams, 1, "hello"))
	assert.Equal(t, 2, scheduler.Len())

	assert.Empty(t, pub.published)
	scheduler.SetPublisher(pub)

	err := scheduler.Start()
	require.NoError(t, err)
	time.Sleep(5 * time.Second)

	err = scheduler.Stop()
	require.NoError(t, err)

	// Let running tasks to complete
	time.Sleep(2 * time.Second)
	assert.False(t, scheduler.IsRunning())

	tasks := scheduler.List()
	assert.Equal(t, 2, len(tasks))
	for _, j := range tasks {
		assert.False(t, j.IsRunning())
		count := j.RunCount()
		assert.GreaterOrEqual(t, count, uint32(3), "Expected count >= 3, actual %d, name: %s", count, j.Name())
		assert.NotNil(t, pub.published[j.ID()])
	}
	assert.GreaterOrEqual(t, pub.runCount, 6)
	assert.GreaterOrEqual(t, pub.stopCount, 6)

	assert.False(t, scheduler.IsRunning())
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
