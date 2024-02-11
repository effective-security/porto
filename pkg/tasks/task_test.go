package tasks

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseTaskFormat(t *testing.T) {
	tests := []struct {
		format   string
		wantTask *task
		wantErr  bool
	}{
		{
			format:   "16:18",
			wantTask: NewTaskDaily(16, 18).(*task),
			wantErr:  false,
		},
		{
			format:   "every 1 second",
			wantTask: NewTaskAtIntervals(1, Seconds).(*task),
			wantErr:  false,
		},
		{
			format:   "every 59 seconds",
			wantTask: NewTaskAtIntervals(59, Seconds).(*task),
			wantErr:  false,
		},
		{
			format:   "every 1 minute",
			wantTask: NewTaskAtIntervals(1, Minutes).(*task),
			wantErr:  false,
		},
		{
			format:   "every 1 hour",
			wantTask: NewTaskAtIntervals(1, Hours).(*task),
			wantErr:  false,
		},
		{
			format:   "every 2 hours",
			wantTask: NewTaskAtIntervals(2, Hours).(*task),
			wantErr:  false,
		},
		{
			format:   "every 61 minutes",
			wantTask: NewTaskAtIntervals(61, Minutes).(*task),
			wantErr:  false,
		},
		{
			format:   "every day",
			wantTask: NewTaskAtIntervals(1, Days).(*task),
			wantErr:  false,
		},
		{
			format:   "every day 11:15",
			wantTask: NewTaskDaily(11, 15).(*task),
			wantErr:  false,
		},
		{
			format:   "every week",
			wantTask: NewTaskAtIntervals(1, Weeks).(*task),
			wantErr:  false,
		},
		{
			format:   "every week 22:11",
			wantTask: NewTaskOnWeekday(time.Sunday, 22, 11).(*task),
			wantErr:  false,
		},

		{
			format:   "1 hour",
			wantTask: NewTaskAtIntervals(1, Hours).(*task),
			wantErr:  false,
		},
		{
			format:   "Monday",
			wantTask: NewTaskOnWeekday(time.Monday, 0, 0).(*task),
			wantErr:  false,
		},
		{
			format:   "every Tuesday 23:59",
			wantTask: NewTaskOnWeekday(time.Tuesday, 23, 59).(*task),
			wantErr:  false,
		},
		{
			format:   "wednesday",
			wantTask: NewTaskOnWeekday(time.Wednesday, 0, 0).(*task),
			wantErr:  false,
		},
		{
			format:   "thursday",
			wantTask: NewTaskOnWeekday(time.Thursday, 0, 0).(*task),
			wantErr:  false,
		},
		{
			format:   "friday",
			wantTask: NewTaskOnWeekday(time.Friday, 0, 0).(*task),
			wantErr:  false,
		},
		{
			format:   "Saturday 23:13",
			wantTask: NewTaskOnWeekday(time.Saturday, 23, 13).(*task),
			wantErr:  false,
		},
		{
			format:   "Sunday 12:00",
			wantTask: NewTaskOnWeekday(time.Sunday, 12, 0).(*task),
			wantErr:  false,
		},
		//
		// Error cases
		//
		{format: "1 second 16:18", wantErr: true},
		{format: "24:00", wantErr: true},
		{format: "Sunday 23:61", wantErr: true},
		{format: "every", wantErr: true},
		{format: "every every 1 second", wantErr: true},
		{format: "every", wantErr: true},
		{format: "2 monday", wantErr: true},
		{format: "3 tuesday", wantErr: true},
		{format: "3 wednesday", wantErr: true},
		{format: "3 thursday", wantErr: true},
		{format: "3 friday", wantErr: true},
		{format: "3 saturday", wantErr: true},
		{format: "3 sunday", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			j, err := NewTask(tt.format)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, j)
				wantSch := tt.wantTask.schedule
				require.NotNil(t, wantSch, tt.format)
				sch := j.(*task).schedule
				require.NotNil(t, sch, tt.format)
				assert.Equal(t, wantSch.Interval, sch.Interval)
				assert.Equal(t, wantSch.Unit, sch.Unit)
				assert.Equal(t, wantSch.Duration(), sch.Duration())
				assert.Equal(t, wantSch.StartDay, sch.StartDay)
				assert.Equal(t, tt.wantTask.Schedule().NextRunAt, j.Schedule().NextRunAt)

				d := j.Schedule().Duration()
				assert.True(t, d > 0)
			}
		})
	}
}

func Test_parseTimeFormat(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		wantHour int
		wantMin  int
		wantErr  bool
	}{
		{
			name:     "normal",
			args:     "16:18",
			wantHour: 16,
			wantMin:  18,
			wantErr:  false,
		},
		{
			name:     "normal",
			args:     "6:18",
			wantHour: 6,
			wantMin:  18,
			wantErr:  false,
		},
		{
			name:     "notnumber",
			args:     "e:18",
			wantHour: 0,
			wantMin:  0,
			wantErr:  true,
		},
		{
			name:     "outofrange",
			args:     "25:18",
			wantHour: 25,
			wantMin:  18,
			wantErr:  true,
		},
		{
			name:     "wrongformat",
			args:     "19:18:17",
			wantHour: 0,
			wantMin:  0,
			wantErr:  true,
		},
		{
			name:     "wrongminute",
			args:     "19:1e",
			wantHour: 19,
			wantMin:  0,
			wantErr:  true,
		},
	}
	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHour, gotMin, err := parseTimeFormat(tt.args)
			if tt.wantErr {
				assert.Error(t, err, fmt.Sprintf("[%d] case failed", idx))
			}
			assert.Equal(t, tt.wantHour, gotHour, "[%d] case failed", idx)
			assert.Equal(t, tt.wantMin, gotMin, "[%d] case failed", idx)
		})
	}
}

func Test_TaskAtIntervalsMinute(t *testing.T) {
	job1 := NewTaskAtIntervals(1, Minutes).Do("test", testTask).(*task)
	executed := job1.Run()
	assert.True(t, executed, "should be able to run")
	t1 := *job1.Schedule().LastRunAt
	t2 := job1.Schedule().NextRunAt
	t.Logf("job1 scheduled for %s, last run was at %s", t2.Format(time.RFC3339), t1.Format(time.RFC3339))
	assert.True(t, t2.After(t1))
	diff := int(t2.Sub(t1).Seconds())
	assert.Equal(t, 60, diff)
}

func Test_TaskOnWeekday(t *testing.T) {
	job1 := NewTaskOnWeekday(time.Monday, 13, 59).Do("test", testTask)
	job2 := NewTaskOnWeekday(time.Wednesday, 13, 59).Do("test", testTask)

	nextTime1 := job1.Schedule().NextRunAt
	nextTime2 := job2.Schedule().NextRunAt
	t.Logf("job1 scheduled for %s", nextTime1)
	t.Logf("job2 scheduled for %s", nextTime2)
	assert.Equal(t, time.Monday, nextTime1.Weekday())
	assert.Equal(t, time.Wednesday, nextTime2.Weekday())
	assert.NotEqual(t, nextTime1, nextTime2, "Two jobs scheduled at the same time on two different weekdays should never run at the same time")
	assert.Equal(t, "test@tasks.testTask", job1.Name())
}

func Test_TaskDaily(t *testing.T) {
	job1 := NewTaskDaily(00, 00).Do("test", testTask)
	job2 := NewTaskDaily(23, 59).Do("test", testTask)
	t.Logf("job1 scheduled for %s", job1.Schedule().NextRunAt)
	t.Logf("job2 scheduled for %s", job2.Schedule().NextRunAt)
	assert.NotEqual(t, job1.Schedule().NextRunAt, job2.Schedule().NextRunAt)
}

func Test_TaskWeekls(t *testing.T) {
	job1 := NewTaskAtIntervals(1, Weeks).Do("test", testTask)
	job2 := NewTaskAtIntervals(2, Weeks).Do("test", testTask)
	t.Logf("job1 scheduled for %s", job1.Schedule().NextRunAt)
	t.Logf("job2 scheduled for %s", job2.Schedule().NextRunAt)
	assert.NotEqual(t, job1.Schedule().NextRunAt, job2.Schedule().NextRunAt)
}

// This ensures that if you schedule a task for today's weekday, but the time is already passed, it will be scheduled for
// next week at the requested time.
func Test_TaskWeekdaysTodayAfter(t *testing.T) {
	now := time.Now()
	month, day, hour, minute := now.Month(), now.Day(), now.Hour(), now.Minute()
	timeToSchedule := time.Date(now.Year(), month, day, hour, minute, 0, 0, time.Local)

	job1 := NewTaskOnWeekday(now.Weekday(), timeToSchedule.Hour(), timeToSchedule.Minute()).Do("test", testTask)
	t.Logf("task is scheduled for %s", job1.Schedule().NextRunAt)
	assert.Equal(t, job1.Schedule().NextRunAt.Weekday(), timeToSchedule.Weekday(), "Task scheduled for current weekday for earlier time, should still be scheduled for current weekday (but next week)")
	//nextWeek := time.Date(now.Year(), month, day+7, hour, minute, 0, 0, time.Local)
	//assert.Equal(t, nextWeek, job1.Schedule().NextRunAt, "Task should be scheduled for the correct time next week.")
}

// This is to ensure that if you schedule a task for today's weekday, and the time hasn't yet passed, the next run time
// will be scheduled for today.
func Test_TaskWeekdaysTodayBefore(t *testing.T) {
	now := TimeNow()
	timeToSchedule := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute()+1, 0, 0, time.Local)

	job1 := NewTaskOnWeekday(now.Weekday(), timeToSchedule.Hour(), timeToSchedule.Minute()).Do("test", testTask)
	t.Logf("task is scheduled for %s", job1.Schedule().NextRunAt)
	assert.Equal(t, timeToSchedule, job1.Schedule().NextRunAt, "Task should be run today, at the set time.")
}

func Test_NewTask_panic(t *testing.T) {
	require.Panics(t, func() {
		NewTaskOnWeekday(time.Wednesday, -1, 60)
	})
	require.Panics(t, func() {
		NewTaskOnWeekday(time.Wednesday, 0, -1)
	})
	require.Panics(t, func() {
		NewTaskDaily(0, -1)
	})
}

func Test_TaskPanicCatch(t *testing.T) {
	job1 := NewTaskAtIntervals(1, Minutes).Do("panicTask", panicTask).(*task)
	executed := job1.Run()
	assert.True(t, executed, "should be able to run")
	assert.False(t, job1.running)
}

func panicTask() {
	logger.Panic("TEST: something went wrong", errors.New("test panic"))
}

func Test_TaskLongTime(t *testing.T) {
	pub := &testPublisher{}
	job1 := NewTaskAtIntervals(1, Seconds, WithPublisher(pub)).Do("longTask1", longTask).(*task)
	job2 := NewTaskAtIntervals(1, Seconds).Do("longTask2", longTask).SetPublisher(pub).(*task)

	var wg sync.WaitGroup

	executed := 0
	skipped := 0
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if job1.Run() {
				executed++
			} else {
				skipped++
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if job2.Run() {
				executed++
			} else {
				skipped++
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 2, executed)
	assert.Equal(t, 4, skipped)
	assert.Equal(t, 2, len(pub.published))
	assert.GreaterOrEqual(t, pub.runCount, 2)
	assert.GreaterOrEqual(t, pub.stopCount, 2)
}

func longTask() {
	logger.Info("TEST: slow task started")
	time.Sleep(3 * time.Second)
}

func Test_TaskUpdate(t *testing.T) {
	tsk, err := NewTask("every 2 hours")
	assert.NoError(t, err)
	assert.NotNil(t, tsk)
	tskI := tsk.(*task)
	sch := tskI.schedule
	assert.Equal(t, uint64(2), sch.Interval)
	assert.Equal(t, Hours, sch.Unit)
	assert.Equal(t, time.Weekday(0), sch.StartDay)
	assert.Equal(t, time.Duration(0), sch.period)
	assert.Equal(t, 2*time.Hour, tsk.Schedule().Duration())
	assert.Equal(t, 2*time.Hour, sch.period)

	tsk.UpdateSchedule("every 7 days")
	require.NoError(t, err)
	assert.NotNil(t, tsk)
	tskI = tsk.(*task)
	sch = tskI.schedule
	assert.Equal(t, uint64(7), sch.Interval)
	assert.Equal(t, Days, sch.Unit)
	assert.Equal(t, time.Weekday(0), sch.StartDay)
	assert.Equal(t, time.Duration(0), sch.period)
	assert.Equal(t, 7*24*time.Hour, tsk.Schedule().Duration())
	assert.Equal(t, 7*24*time.Hour, sch.period)
	//assert.Equal(t, time.Unix(0, 0), sch.NextRunAt)
}

func Test_schedulesEqual(t *testing.T) {
	type schedule struct {
		s1    string
		s2    string
		equal bool
	}

	tests := []schedule{
		{s1: "every Saturday 16:00", s2: "every 7 days", equal: false},
		{s1: "every Saturday 16:00", s2: "every Sunday 16:00", equal: false},
		{s1: "every Saturday 16:00", s2: "every Saturday 17:00", equal: false},
		{s1: "every Saturday", s2: "every Monday", equal: false},
		{s1: "every 2 days", s2: "every 3 days", equal: false},
		{s1: "every day", s2: "every 2 days", equal: false},
		{s1: "every Saturday 16:00", s2: "every Saturday 16:00", equal: true},
		{s1: "every Saturday", s2: "every Saturday", equal: true},
		{s1: "every Monday", s2: "every Monday", equal: true},
		{s1: "every 2 days", s2: "every 2 days", equal: true},
	}

	for _, tc := range tests {
		s1, err := ParseSchedule(tc.s1)
		assert.NoError(t, err)
		s2, err := ParseSchedule(tc.s2)
		assert.NoError(t, err)
		equal := s1.Equal(s2)
		assert.Equal(t, tc.equal, equal)
	}
}
