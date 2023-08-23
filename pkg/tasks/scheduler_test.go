package tasks

import (
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

func Test_StartAndStop(t *testing.T) {
	scheduler := NewScheduler().(*scheduler)
	require.NotNil(t, scheduler)
	defer scheduler.Stop()

	scheduler.Add(NewTaskAtIntervals(1, Seconds).Do("test", testTask))
	scheduler.Add(NewTaskAtIntervals(1, Seconds).Do("test", taskWithParams, 1, "hello"))
	assert.Equal(t, 2, scheduler.Len())
	err := scheduler.Start()
	require.NoError(t, err)
	time.Sleep(5 * time.Second)
	err = scheduler.Stop()
	require.NoError(t, err)

	// Let running tasks to complete
	time.Sleep(1 * time.Second)

	tasks := scheduler.getAllTasks()
	assert.Equal(t, 2, len(tasks))
	for _, j := range tasks {
		assert.False(t, j.(*task).running)
		count := j.RunCount()
		assert.True(t, count >= 3, "Expected retry count >= 3, actual %d, name: %s", count, j.Name())
	}

	assert.True(t, scheduler.IsRunning())
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

	t1, err := NewTaskWithID("test1", "every 5 hours")
	require.NoError(t, err)
	require.Equal(t, "test1", t1.ID())

	t2, err := NewTaskWithID("test2", "every 5 hours")
	require.NoError(t, err)
	require.Equal(t, "test2", t2.ID())

	scheduler.Add(t1)
	scheduler.Add(t2)
	assert.Equal(t, 2, scheduler.Count())

	t11, err := scheduler.Get(t1.ID())
	require.NoError(t, err)
	require.Equal(t, t1, t11)

	t12, err := scheduler.Get(t2.ID())
	require.NoError(t, err)
	require.Equal(t, t2, t12)

	t13, err := scheduler.Get("test3")
	require.Error(t, err)
	require.Nil(t, t13)

	scheduler.Clear()
	assert.Equal(t, 0, scheduler.Count())
}
