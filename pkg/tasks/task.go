package tasks

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

// TimeUnit specifies the time unit: 'minutes', 'hours'...
type TimeUnit uint

const (
	// Never specifies the time unit to never run a task
	Never TimeUnit = iota
	// Seconds specifies the time unit in seconds
	Seconds
	// Minutes specifies the time unit in minutes
	Minutes
	// Hours specifies the time unit in hours
	Hours
	// Days specifies the time unit in days
	Days
	// Weeks specifies the time unit in weeks
	Weeks
)

// Task defines task interface
type Task interface {
	// Name returns a name of the task
	Name() string
	// RunCount species the number of times the task executed
	RunCount() uint32
	// NextScheduledTime returns the time of when this task is to run next
	NextScheduledTime() time.Time
	// LastRunTime returns the time of last run
	LastRunTime() time.Time
	// Duration returns interval between runs
	Duration() time.Duration

	// ShouldRun returns true if the task should be run now
	ShouldRun() bool

	// Run will try to run the task, if it's not already running
	// and immediately reschedule it after run
	Run() bool

	// Do accepts a function that should be called every time the task runs
	Do(taskName string, task interface{}, params ...interface{}) Task
}

// task describes a task schedule
type task struct {
	// pause interval * unit bettween runs
	interval uint64
	// time units, ,e.g. 'minutes', 'hours'...
	unit TimeUnit
	// number of runs
	count uint32
	// datetime of last run
	lastRunAt *time.Time
	// datetime of next run
	nextRunAt time.Time
	// cache the period between last an next run
	period time.Duration
	// Specific day of the week to start on
	startDay time.Weekday

	// the task name
	name string
	// callback is the function to execute
	callback reflect.Value
	// params for the callback functions
	params []reflect.Value

	runLock chan struct{}
	running bool
	// timeout interval to schedule a run
	runTimeout time.Duration
}

// DefaultRunTimeoutInterval specify a timeout for a task to start
const DefaultRunTimeoutInterval = time.Second

// NewTaskAtIntervals creates a new task with the time interval.
func NewTaskAtIntervals(interval uint64, unit TimeUnit) Task {
	return &task{
		interval:   interval,
		unit:       unit,
		lastRunAt:  nil,
		nextRunAt:  time.Unix(0, 0),
		period:     0,
		startDay:   time.Sunday,
		runLock:    make(chan struct{}, 1),
		count:      0,
		runTimeout: DefaultRunTimeoutInterval,
	}
}

// NewTaskOnWeekday creates a new task to execute on specific day of the week.
func NewTaskOnWeekday(startDay time.Weekday, hour, minute int) Task {
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		logger.Panicf("invalid time value: time='%d:%d'", hour, minute)
	}
	j := &task{
		interval:   1,
		unit:       Weeks,
		lastRunAt:  nil,
		nextRunAt:  time.Unix(0, 0),
		period:     0,
		startDay:   startDay,
		runLock:    make(chan struct{}, 1),
		count:      0,
		runTimeout: DefaultRunTimeoutInterval,
	}
	return j.at(hour, minute)
}

// NewTaskDaily creates a new task to execute daily at specific time
func NewTaskDaily(hour, minute int) Task {
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		logger.Panicf("invalid time value:, time='%d:%d'", hour, minute)
	}
	j := &task{
		interval:   1,
		unit:       Days,
		lastRunAt:  nil,
		nextRunAt:  time.Unix(0, 0),
		period:     0,
		startDay:   time.Sunday,
		runLock:    make(chan struct{}, 1),
		count:      0,
		runTimeout: DefaultRunTimeoutInterval,
	}
	return j.at(hour, minute)
}

// NewTask creates a new task from parsed format string.
// every %d
// seconds | minutes | ...
// Monday | .. | Sunday
// at %hh:mm
func NewTask(format string) (Task, error) {
	return parseTaskFormat(format)
}

// Name returns a name of the task
func (j *task) Name() string {
	return j.name
}

// RunCount species the number of times the task executed
func (j *task) RunCount() uint32 {
	return atomic.LoadUint32(&j.count)
}

// ShouldRun returns true if the task should be run now
func (j *task) ShouldRun() bool {
	return !j.running && time.Now().After(j.nextRunAt)
}

// NextScheduledTime returns the time of when this task is to run next
func (j *task) NextScheduledTime() time.Time {
	return j.nextRunAt
}

// LastRunTime returns the time of last run
func (j *task) LastRunTime() time.Time {
	if j.lastRunAt != nil {
		return *j.lastRunAt
	}
	return time.Unix(0, 0)
}

// // Duration returns interval between runs
func (j *task) Duration() time.Duration {
	if j.period == 0 {
		switch j.unit {
		case Seconds:
			j.period = time.Duration(j.interval) * time.Second
		case Minutes:
			j.period = time.Duration(j.interval) * time.Minute
		case Hours:
			j.period = time.Duration(j.interval) * time.Hour
		case Days:
			j.period = time.Duration(j.interval) * time.Hour * 24
		case Weeks:
			j.period = time.Duration(j.interval) * time.Hour * 24 * 7
		}
	}
	return j.period
}

// Do accepts a function that should be called every time the task runs
func (j *task) Do(taskName string, taskFunc interface{}, params ...interface{}) Task {
	typ := reflect.TypeOf(taskFunc)
	if typ.Kind() != reflect.Func {
		logger.Panic("only function can be scheduled into the task queue")
	}

	j.name = fmt.Sprintf("%s@%s", taskName, filepath.Base(getFunctionName(taskFunc)))
	j.callback = reflect.ValueOf(taskFunc)
	if len(params) != j.callback.Type().NumIn() {
		logger.Panicf("the number of parameters does not match the function")
	}
	j.params = make([]reflect.Value, len(params))
	for k, param := range params {
		j.params[k] = reflect.ValueOf(param)
	}

	//schedule the next run
	j.scheduleNextRun()

	return j
}

func (j *task) at(hour, min int) *task {
	y, m, d := time.Now().Date()

	// time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	mock := time.Date(y, m, d, hour, min, 0, 0, loc)

	if j.unit == Days {
		if !time.Now().After(mock) {
			// remove 1 day
			mock = mock.UTC().AddDate(0, 0, -1).Local()
		}
	} else if j.unit == Weeks {
		if j.startDay != time.Now().Weekday() || (time.Now().After(mock) && j.startDay == time.Now().Weekday()) {
			i := int(mock.Weekday() - j.startDay)
			if i < 0 {
				i = 7 + i
			}
			mock = mock.UTC().AddDate(0, 0, -i).Local()
		} else {
			// remove 1 week
			mock = mock.UTC().AddDate(0, 0, -7).Local()
		}
	}
	j.lastRunAt = &mock
	return j
}

// scheduleNextRun computes the instant when this task should run next
func (j *task) scheduleNextRun() time.Time {
	now := time.Now()
	if j.lastRunAt == nil {
		if j.unit == Weeks {
			i := now.Weekday() - j.startDay
			if i < 0 {
				i = 7 + i
			}
			y, m, d := now.Date()
			now = time.Date(y, m, d-int(i), 0, 0, 0, 0, loc)
		}
		j.lastRunAt = &now
	}

	j.nextRunAt = j.lastRunAt.Add(j.Duration())
	/*
		logger.KV(xlog.DEBUG,
			"lastRunAt",j.lastRunAt.Format(time.RFC3339),
			"nextRunAt",j.nextRunAt.Format(time.RFC3339),
			"task",j.Name())
	*/
	return j.nextRunAt
}

// for given function fn, get the name of function.
func getFunctionName(fn interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf((fn)).Pointer()).Name()
}

// Run will try to run the task, if it's not already running
// and immediately reschedule it after run
func (j *task) Run() bool {
	timeout := j.runTimeout
	if timeout == 0 {
		timeout = DefaultRunTimeoutInterval
	}

	timer := time.NewTimer(timeout)
	select {
	case j.runLock <- struct{}{}:
		timer.Stop()
		now := time.Now()
		j.lastRunAt = &now
		j.running = true
		count := atomic.AddUint32(&j.count, 1)

		logger.KV(xlog.DEBUG,
			"status", "running",
			"count", count,
			"started_at", j.lastRunAt,
			"task", j.Name())

		j.callback.Call(j.params)
		j.running = false
		j.scheduleNextRun()
		<-j.runLock
		return true
	case <-time.After(timeout):
	}

	logger.KV(xlog.DEBUG,
		"status", "already_running",
		"count", j.count,
		"started_at", j.lastRunAt,
		"task", j.Name())

	return false
}

func parseTimeFormat(t string) (hour, min int, err error) {
	var errTimeFormat = errors.Errorf("time format not valid: %q", t)
	ts := strings.Split(t, ":")
	if len(ts) != 2 {
		err = errors.WithStack(errTimeFormat)
		return
	}

	hour, err = strconv.Atoi(ts[0])
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	min, err = strconv.Atoi(ts[1])
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	if hour < 0 || hour > 23 || min < 0 || min > 59 {
		err = errors.WithStack(errTimeFormat)
		return
	}
	return
}

func parseTaskFormat(format string) (*task, error) {
	var errTimeFormat = errors.Errorf("task format not valid: %q", format)

	j := &task{
		interval:  0,
		unit:      Never,
		lastRunAt: nil,
		nextRunAt: time.Unix(0, 0),
		period:    0,
		startDay:  time.Sunday,
		runLock:   make(chan struct{}, 1),
		count:     0,
	}

	ts := strings.Split(strings.ToLower(format), " ")
	for _, t := range ts {
		switch t {
		case "every":
			if j.interval > 0 {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.interval = 1
		case "second", "seconds":
			j.unit = Seconds
		case "minute", "minutes":
			j.unit = Minutes
		case "hour", "hours":
			j.unit = Hours
		case "day", "days":
			j.unit = Days
		case "week", "weeks":
			j.unit = Weeks
		case "monday":
			if j.interval > 1 || j.unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.unit = Weeks
			j.startDay = time.Monday
		case "tuesday":
			if j.interval > 1 || j.unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.unit = Weeks
			j.startDay = time.Tuesday
		case "wednesday":
			if j.interval > 1 || j.unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.unit = Weeks
			j.startDay = time.Wednesday
		case "thursday":
			if j.interval > 1 || j.unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.unit = Weeks
			j.startDay = time.Thursday
		case "friday":
			if j.interval > 1 || j.unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.unit = Weeks
			j.startDay = time.Friday
		case "saturday":
			if j.interval > 1 || j.unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.unit = Weeks
			j.startDay = time.Saturday
		case "sunday":
			if j.interval > 1 || j.unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.unit = Weeks
			j.startDay = time.Sunday
		default:
			if strings.Contains(t, ":") {
				hour, min, err := parseTimeFormat(t)
				if err != nil {
					return nil, errors.WithStack(errTimeFormat)
				}
				if j.unit == Never {
					j.unit = Days
				} else if j.unit != Days && j.unit != Weeks {
					return nil, errors.WithStack(errTimeFormat)
				}
				j.at(hour, min)
			} else {
				if j.interval > 1 {
					return nil, errors.WithStack(errTimeFormat)
				}
				interval, err := strconv.ParseUint(t, 10, 0)
				if err != nil || interval < 1 {
					return nil, errors.WithStack(errTimeFormat)
				}
				j.interval = interval
			}
		}
	}
	if j.interval == 0 {
		j.interval = 1
	}
	if j.unit == Never {
		return nil, errors.WithStack(errTimeFormat)
	}

	return j, nil
}
