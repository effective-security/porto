package tasks

import (
	"fmt"
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
			j, err := parseTaskFormat(tt.format)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, j)
				assert.Equal(t, tt.wantTask.interval, j.interval)
				assert.Equal(t, tt.wantTask.unit, j.unit)
				assert.Equal(t, tt.wantTask.period, j.period)
				assert.Equal(t, tt.wantTask.startDay, j.startDay)
				assert.Equal(t, tt.wantTask.NextScheduledTime(), j.NextScheduledTime())

				d := j.Duration()
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
	t1 := job1.LastRunTime()
	t2 := job1.NextScheduledTime()
	t.Logf("job1 scheduled for %s, last run was at %s", t2.Format(time.RFC3339), t1.Format(time.RFC3339))
	assert.True(t, t2.After(t1))
	diff := int(t2.Sub(t1).Seconds())
	assert.Equal(t, 60, diff)
}

func Test_TaskOnWeekday(t *testing.T) {
	job1 := NewTaskOnWeekday(time.Monday, 23, 59).Do("test", testTask)
	job2 := NewTaskOnWeekday(time.Wednesday, 23, 59).Do("test", testTask)

	nextTime1 := job1.NextScheduledTime()
	nextTime2 := job2.NextScheduledTime()
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
	t.Logf("job1 scheduled for %s", job1.NextScheduledTime())
	t.Logf("job2 scheduled for %s", job2.NextScheduledTime())
	assert.NotEqual(t, job1.NextScheduledTime(), job2.NextScheduledTime())
}

func Test_TaskWeekls(t *testing.T) {
	job1 := NewTaskAtIntervals(1, Weeks).Do("test", testTask)
	job2 := NewTaskAtIntervals(2, Weeks).Do("test", testTask)
	t.Logf("job1 scheduled for %s", job1.NextScheduledTime())
	t.Logf("job2 scheduled for %s", job2.NextScheduledTime())
	assert.NotEqual(t, job1.NextScheduledTime(), job2.NextScheduledTime())
}

// This ensures that if you schedule a task for today's weekday, but the time is already passed, it will be scheduled for
// next week at the requested time.
func Test_TaskWeekdaysTodayAfter(t *testing.T) {
	now := time.Now()
	month, day, hour, minute := now.Month(), now.Day(), now.Hour(), now.Minute()
	timeToSchedule := time.Date(now.Year(), month, day, hour, minute, 0, 0, time.Local)

	job1 := NewTaskOnWeekday(now.Weekday(), timeToSchedule.Hour(), timeToSchedule.Minute()).Do("test", testTask)
	t.Logf("task is scheduled for %s", job1.NextScheduledTime())
	assert.Equal(t, job1.NextScheduledTime().Weekday(), timeToSchedule.Weekday(), "Task scheduled for current weekday for earlier time, should still be scheduled for current weekday (but next week)")
	//nextWeek := time.Date(now.Year(), month, day+7, hour, minute, 0, 0, time.Local)
	//assert.Equal(t, nextWeek, job1.NextScheduledTime(), "Task should be scheduled for the correct time next week.")
}

// This is to ensure that if you schedule a task for today's weekday, and the time hasn't yet passed, the next run time
// will be scheduled for today.
func Test_TaskWeekdaysTodayBefore(t *testing.T) {

	now := time.Now()
	timeToSchedule := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute()+1, 0, 0, time.Local)

	job1 := NewTaskOnWeekday(now.Weekday(), timeToSchedule.Hour(), timeToSchedule.Minute()).Do("test", testTask)
	t.Logf("task is scheduled for %s", job1.NextScheduledTime())
	assert.Equal(t, timeToSchedule, job1.NextScheduledTime(), "Task should be run today, at the set time.")
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
