package tasks

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publisherFunc func(Task)

func (f publisherFunc) Publish(task Task) { f(task) }

func TestSchedulerStopAndRestart(t *testing.T) {
	t.Parallel()

	s := NewScheduler(WithTickerInterval(time.Millisecond))
	require.NoError(t, s.Start())
	const callers = 16
	var workers sync.WaitGroup
	results := make(chan error, callers)
	for range callers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- s.Stop()
		}()
	}
	workers.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	assert.False(t, s.IsRunning())
	require.NoError(t, s.Start())
	assert.True(t, s.IsRunning())
	require.NoError(t, s.Stop())
}

func TestSchedulerListSnapshot(t *testing.T) {
	t.Parallel()

	s := NewScheduler()
	first := NewTaskAtIntervals(1, Seconds, WithID("first"))
	second := NewTaskAtIntervals(1, Seconds, WithID("second"))
	s.Add(first).Add(second)

	listed := s.List()
	require.Len(t, listed, 2)
	listed[0] = nil
	assert.NotNil(t, s.Get("first"))
	assert.NotNil(t, s.Get("second"))
	assert.Equal(t, 2, s.Count())

	s.Clear()
	assert.Empty(t, s.List())
	assert.Len(t, listed, 2)
}

func TestSchedulerConcurrentAccess(t *testing.T) {
	t.Parallel()

	s := NewScheduler(WithTickerInterval(time.Millisecond))
	base := NewTaskAtIntervals(1, Seconds, WithID("base")).Do("base", func() {})
	s.Add(base)
	require.NoError(t, s.Start())
	defer s.Stop()

	const iterations = 100
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for i := range iterations {
			s.Add(NewTaskAtIntervals(1, Seconds, WithID(fmt.Sprintf("task-%d", i))).Do("noop", func() {}))
			if i%10 == 0 {
				s.Clear()
				s.Add(base)
			}
		}
		results <- nil
	}()
	go func() {
		defer workers.Done()
		<-start
		for range iterations {
			_ = s.Count()
			_ = s.Get("base")
			for _, task := range s.List() {
				if task == nil {
					results <- errors.New("List returned a nil task")
					return
				}
			}
		}
		results <- nil
	}()
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
}

func TestTaskScheduleSnapshotAndConcurrentState(t *testing.T) {
	t.Parallel()

	now := time.Now()
	input := &Schedule{
		Interval:  1,
		Unit:      Seconds,
		LastRunAt: &now,
		NextRunAt: now.Add(time.Second),
	}
	started := make(chan struct{})
	release := make(chan struct{})
	task := New(input).Do("blocking", func() {
		close(started)
		<-release
	})
	input.NextRunAt = time.Time{}
	snapshot := task.Schedule()
	snapshot.LastRunAt = nil
	snapshot.NextRunAt = time.Time{}
	assert.False(t, task.Schedule().NextRunAt.IsZero())
	assert.NotNil(t, task.Schedule().LastRunAt)

	done := make(chan bool, 1)
	go func() { done <- task.Run() }()
	<-started
	for range 100 {
		assert.True(t, task.IsRunning())
		assert.Equal(t, uint32(1), task.RunCount())
		_ = task.ShouldRun()
		_ = task.Schedule()
		task.SetNextRun(time.Second)
	}
	close(release)
	assert.True(t, <-done)
	assert.False(t, task.IsRunning())
}

func TestSchedulerPublisherMayInspectScheduler(t *testing.T) {
	t.Parallel()

	s := NewScheduler()
	s.Add(NewTaskAtIntervals(1, Seconds).Do("noop", func() {}))
	s.SetPublisher(publisherFunc(func(Task) {
		_ = s.Count()
		_ = s.List()
	}))
	require.NoError(t, s.Start())
	require.NoError(t, s.Stop())
}
