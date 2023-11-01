package tasks

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/effective-security/porto/x/guid"
	"github.com/effective-security/porto/x/slices"
	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

// TimeUnit specifies the time unit: 'minutes', 'hours'...
type TimeUnit uint

// TimeNow is a function that returns the current time
var TimeNow = time.Now

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
	// ID returns the id of the task
	ID() string
	// Name returns a name of the task
	Name() string
	// RunCount species the number of times the task executed
	RunCount() uint32
	// Schedule returns the task schedule
	Schedule() *Schedule
	// UpdateSchedule updates the task with the new format
	UpdateSchedule(format string) error
	// ShouldRun returns true if the task should be run now
	ShouldRun() bool
	// Run will try to run the task, if it's not already running
	// and immediately reschedule it after run
	Run() bool
	// SetNextRun updates next schedule time
	SetNextRun(time.Duration) Task
	// Do accepts a function that should be called every time the task runs
	Do(taskName string, task interface{}, params ...interface{}) Task
}

// Schedule defines task schedule
type Schedule struct {
	// Interval * unit bettween runs
	Interval uint64
	// Unit specifies time units, ,e.g. 'minutes', 'hours'...
	Unit TimeUnit
	// StartDay specifies day of the week to start on
	StartDay time.Weekday
	// LastRunAt specifies datetime of last run
	LastRunAt *time.Time
	// NextRunAt specifies datetime of next run
	NextRunAt time.Time

	// cache the period between last an next run
	period time.Duration
}

// task describes a task schedule
type task struct {
	// id is unique guide assigned to the task
	id       string
	schedule *Schedule
	// number of runs
	count uint32
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
func NewTaskAtIntervals(interval uint64, unit TimeUnit, ops ...Option) Task {
	s := &Schedule{
		Interval:  interval,
		Unit:      unit,
		LastRunAt: nil,
		NextRunAt: time.Unix(0, 0),
		StartDay:  time.Sunday,
	}
	return New(s, ops...)
}

// NewTaskOnWeekday creates a new task to execute on specific day of the week.
func NewTaskOnWeekday(startDay time.Weekday, hour, minute int, ops ...Option) Task {
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		logger.Panicf("invalid time value: time='%d:%d'", hour, minute)
	}
	s := &Schedule{
		Interval:  1,
		Unit:      Weeks,
		LastRunAt: nil,
		NextRunAt: time.Unix(0, 0),
		StartDay:  startDay,
	}
	s.at(hour, minute)

	return New(s, ops...)
}

// NewTaskDaily creates a new task to execute daily at specific time
func NewTaskDaily(hour, minute int, ops ...Option) Task {
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		logger.Panicf("invalid time value:, time='%d:%d'", hour, minute)
	}
	s := &Schedule{
		Interval:  1,
		Unit:      Days,
		LastRunAt: nil,
		NextRunAt: time.Unix(0, 0),
		StartDay:  time.Sunday,
	}
	s.at(hour, minute)

	return New(s, ops...)
}

// NewTask creates a new task from parsed format string.
// every %d
// seconds | minutes | ...
// Monday | .. | Sunday
// at %hh:mm
func NewTask(format string, ops ...Option) (Task, error) {
	s, err := ParseSchedule(format)
	if err != nil {
		return nil, err
	}

	return New(s, ops...), nil
}

// New returns new task
func New(s *Schedule, ops ...Option) Task {
	dops := options{
		id:         guid.MustCreate(),
		runTimeout: DefaultRunTimeoutInterval,
	}
	for _, op := range ops {
		op.apply(&dops)
	}

	dops.id = slices.StringsCoalesce(dops.id, guid.MustCreate())
	j := &task{
		id:         dops.id,
		schedule:   s,
		runLock:    make(chan struct{}, 1),
		count:      0,
		runTimeout: dops.runTimeout,
	}

	return j
}

// UpdateSchedule updates the task with a new schedule
func (j *task) UpdateSchedule(format string) error {
	s, err := ParseSchedule(format)
	if err != nil {
		return err
	}
	j.schedule = s
	return nil
}

// SetNextRun updates next schedule time
func (j *task) SetNextRun(after time.Duration) Task {
	j.schedule.NextRunAt = TimeNow().Add(after)
	return j
}

// ID returns a id of the task
func (j *task) ID() string {
	return j.id
}

// Name returns a name of the task
func (j *task) Name() string {
	return j.name
}

// Schedule returns the task schedule
func (j *task) Schedule() *Schedule {
	return j.schedule
}

// RunCount species the number of times the task executed
func (j *task) RunCount() uint32 {
	return atomic.LoadUint32(&j.count)
}

// ShouldRun returns true if the task should be run now
func (j *task) ShouldRun() bool {
	return !j.running && j.schedule.ShouldRun()
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
	j.schedule.UpdateNextRun()

	return j
}

func (j *Schedule) at(hour, min int) *Schedule {
	now := TimeNow()
	y, m, d := now.Date()

	// time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	mock := time.Date(y, m, d, hour, min, 0, 0, loc)

	if j.Unit == Days {
		if !now.After(mock) {
			// remove 1 day
			mock = mock.UTC().AddDate(0, 0, -1).Local()
		}
	} else if j.Unit == Weeks {
		if j.StartDay != now.Weekday() || (now.After(mock) && j.StartDay == now.Weekday()) {
			i := int(mock.Weekday() - j.StartDay)
			if i < 0 {
				i = 7 + i
			}
			mock = mock.UTC().AddDate(0, 0, -i).Local()
		} else {
			// remove 1 week
			mock = mock.UTC().AddDate(0, 0, -7).Local()
		}
	}
	j.LastRunAt = &mock
	return j
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
		now := TimeNow()
		j.schedule.LastRunAt = &now
		j.running = true
		count := atomic.AddUint32(&j.count, 1)

		logger.KV(xlog.DEBUG,
			"status", "running",
			"count", count,
			"started_at", j.schedule.LastRunAt,
			"task", j.Name())

		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.KV(xlog.ERROR,
						"reason", "panic",
						"task", j.Name(),
						"err", r,
						"stack", string(debug.Stack()))
				}
			}()
			j.callback.Call(j.params)
		}()

		j.running = false
		j.schedule.UpdateNextRun()
		<-j.runLock
		return true
	case <-time.After(timeout):
	}

	logger.KV(xlog.DEBUG,
		"status", "already_running",
		"count", j.count,
		"started_at", j.schedule.LastRunAt,
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

// ParseSchedule parses a schedule string
func ParseSchedule(format string) (*Schedule, error) {
	var errTimeFormat = errors.Errorf("task format not valid: %q", format)

	j := &Schedule{
		Interval:  0,
		Unit:      Never,
		LastRunAt: nil,
		NextRunAt: time.Unix(0, 0),
		StartDay:  time.Sunday,
	}

	ts := strings.Split(strings.ToLower(format), " ")
	for _, t := range ts {
		switch t {
		case "every":
			if j.Interval > 0 {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.Interval = 1
		case "second", "seconds":
			j.Unit = Seconds
		case "minute", "minutes":
			j.Unit = Minutes
		case "hour", "hours":
			j.Unit = Hours
		case "day", "days":
			j.Unit = Days
		case "week", "weeks":
			j.Unit = Weeks
		case "monday":
			if j.Interval > 1 || j.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.Unit = Weeks
			j.StartDay = time.Monday
		case "tuesday":
			if j.Interval > 1 || j.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.Unit = Weeks
			j.StartDay = time.Tuesday
		case "wednesday":
			if j.Interval > 1 || j.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.Unit = Weeks
			j.StartDay = time.Wednesday
		case "thursday":
			if j.Interval > 1 || j.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.Unit = Weeks
			j.StartDay = time.Thursday
		case "friday":
			if j.Interval > 1 || j.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.Unit = Weeks
			j.StartDay = time.Friday
		case "saturday":
			if j.Interval > 1 || j.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.Unit = Weeks
			j.StartDay = time.Saturday
		case "sunday":
			if j.Interval > 1 || j.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			j.Unit = Weeks
			j.StartDay = time.Sunday
		default:
			if strings.Contains(t, ":") {
				hour, min, err := parseTimeFormat(t)
				if err != nil {
					return nil, errors.WithStack(errTimeFormat)
				}
				if j.Unit == Never {
					j.Unit = Days
				} else if j.Unit != Days && j.Unit != Weeks {
					return nil, errors.WithStack(errTimeFormat)
				}
				j.at(hour, min)
			} else {
				if j.Interval > 1 {
					return nil, errors.WithStack(errTimeFormat)
				}
				interval, err := strconv.ParseUint(t, 10, 0)
				if err != nil || interval < 1 {
					return nil, errors.WithStack(errTimeFormat)
				}
				j.Interval = interval
			}
		}
	}
	if j.Interval == 0 {
		j.Interval = 1
	}
	if j.Unit == Never {
		return nil, errors.WithStack(errTimeFormat)
	}

	return j, nil
}

// ShouldRun returns true if the task should be run now
func (j *Schedule) ShouldRun() bool {
	return TimeNow().After(j.NextRunAt)
}

// UpdateNextRun computes the instant when this task should run next
func (j *Schedule) UpdateNextRun() time.Time {
	now := TimeNow()
	if j.LastRunAt == nil {
		if j.Unit == Weeks {
			i := now.Weekday() - j.StartDay
			if i < 0 {
				i = 7 + i
			}
			y, m, d := now.Date()
			now = time.Date(y, m, d-int(i), 0, 0, 0, 0, loc)
		}
		j.LastRunAt = &now
	}

	j.NextRunAt = j.LastRunAt.Add(j.Duration())

	return j.NextRunAt
}

// // Duration returns interval between runs
func (j *Schedule) Duration() time.Duration {
	if j.period == 0 {
		switch j.Unit {
		case Seconds:
			j.period = time.Duration(j.Interval) * time.Second
		case Minutes:
			j.period = time.Duration(j.Interval) * time.Minute
		case Hours:
			j.period = time.Duration(j.Interval) * time.Hour
		case Days:
			j.period = time.Duration(j.Interval) * time.Hour * 24
		case Weeks:
			j.period = time.Duration(j.Interval) * time.Hour * 24 * 7
		}
	}
	return j.period
}
