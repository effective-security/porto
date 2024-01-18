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

	"github.com/effective-security/x/guid"
	"github.com/effective-security/x/values"
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
	// IsRunning return the status
	IsRunning() bool
	// SetPublisher sets a publisher for the task, when the status changes
	SetPublisher(Publisher) Task
	// Publish publishes the task status
	Publish()
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
	// RunCount specifies the number of runs
	RunCount uint32
	// cache the period between last an next run
	period time.Duration
}

// GetLastRun returns the last run time
func (s *Schedule) GetLastRun() *time.Time {
	if s.LastRunAt == nil || s.RunCount == 0 {
		return nil
	}
	return s.LastRunAt
}

// task describes a task schedule
type task struct {
	// id is unique guide assigned to the task
	id       string
	schedule *Schedule
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
	publisher  Publisher
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

	dops.id = values.StringsCoalesce(dops.id, guid.MustCreate())
	j := &task{
		id:         dops.id,
		schedule:   s,
		runLock:    make(chan struct{}, 1),
		runTimeout: dops.runTimeout,
		publisher:  dops.publisher,
	}

	return j
}

// SetPublisher sets the publisher for all tasks
func (j *task) SetPublisher(pub Publisher) Task {
	j.publisher = pub
	return j
}

// Publish the current state
func (j *task) Publish() {
	if j.publisher != nil {
		j.publisher.Publish(j)
	}
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
	return atomic.LoadUint32(&j.schedule.RunCount)
}

// ShouldRun returns true if the task should be run now
func (j *task) ShouldRun() bool {
	return !j.running && j.schedule.ShouldRun()
}

// IsRunning return the status
func (j *task) IsRunning() bool {
	return j.running
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

func (s *Schedule) at(hour, min int) *Schedule {
	now := TimeNow()
	y, m, d := now.Date()

	lastRun := time.Date(y, m, d, hour, min, 0, 0, loc)

	if s.Unit == Days {
		if !now.After(lastRun) {
			// remove 1 day
			lastRun = lastRun.UTC().AddDate(0, 0, -1).Local()
		}
	} else if s.Unit == Weeks {
		if s.StartDay != now.Weekday() || (now.After(lastRun) && s.StartDay == now.Weekday()) {
			i := int(lastRun.Weekday() - s.StartDay)
			if i < 0 {
				i = 7 + i
			}
			lastRun = lastRun.UTC().AddDate(0, 0, -i).Local()
		} else {
			// remove 1 week
			lastRun = lastRun.UTC().AddDate(0, 0, -7).Local()
		}
	}
	s.LastRunAt = &lastRun
	return s
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
		count := atomic.AddUint32(&j.schedule.RunCount, 1)

		logger.KV(xlog.DEBUG,
			"status", "running",
			"run_count", count,
			"started_at", j.schedule.LastRunAt,
			"task", j.Name())

		j.Publish()

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
		j.Publish()

		<-j.runLock
		return true
	case <-time.After(timeout):
	}

	logger.KV(xlog.DEBUG,
		"status", "already_running",
		"run_count", j.schedule.RunCount,
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

	s := &Schedule{
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
			if s.Interval > 0 {
				return nil, errors.WithStack(errTimeFormat)
			}
			s.Interval = 1
		case "second", "seconds":
			s.Unit = Seconds
		case "minute", "minutes":
			s.Unit = Minutes
		case "hour", "hours":
			s.Unit = Hours
		case "day", "days":
			s.Unit = Days
		case "week", "weeks":
			s.Unit = Weeks
		case "monday":
			if s.Interval > 1 || s.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			s.Unit = Weeks
			s.StartDay = time.Monday
		case "tuesday":
			if s.Interval > 1 || s.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			s.Unit = Weeks
			s.StartDay = time.Tuesday
		case "wednesday":
			if s.Interval > 1 || s.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			s.Unit = Weeks
			s.StartDay = time.Wednesday
		case "thursday":
			if s.Interval > 1 || s.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			s.Unit = Weeks
			s.StartDay = time.Thursday
		case "friday":
			if s.Interval > 1 || s.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			s.Unit = Weeks
			s.StartDay = time.Friday
		case "saturday":
			if s.Interval > 1 || s.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			s.Unit = Weeks
			s.StartDay = time.Saturday
		case "sunday":
			if s.Interval > 1 || s.Unit != Never {
				return nil, errors.WithStack(errTimeFormat)
			}
			s.Unit = Weeks
			s.StartDay = time.Sunday
		default:
			if strings.Contains(t, ":") {
				hour, min, err := parseTimeFormat(t)
				if err != nil {
					return nil, errors.WithStack(errTimeFormat)
				}
				if s.Unit == Never {
					s.Unit = Days
				} else if s.Unit != Days && s.Unit != Weeks {
					return nil, errors.WithStack(errTimeFormat)
				}
				s.at(hour, min)
			} else {
				if s.Interval > 1 {
					return nil, errors.WithStack(errTimeFormat)
				}
				interval, err := strconv.ParseUint(t, 10, 0)
				if err != nil || interval < 1 {
					return nil, errors.WithStack(errTimeFormat)
				}
				s.Interval = interval
			}
		}
	}
	if s.Interval == 0 {
		s.Interval = 1
	}
	if s.Unit == Never {
		return nil, errors.WithStack(errTimeFormat)
	}

	return s, nil
}

// ShouldRun returns true if the task should be run now
func (s *Schedule) ShouldRun() bool {
	return TimeNow().After(s.NextRunAt)
}

// UpdateNextRun computes the instant when this task should run next
func (s *Schedule) UpdateNextRun() time.Time {
	now := TimeNow()
	if s.LastRunAt == nil {
		if s.Unit == Weeks {
			i := now.Weekday() - s.StartDay
			if i < 0 {
				i = 7 + i
			}
			y, m, d := now.Date()
			now = time.Date(y, m, d-int(i), 0, 0, 0, 0, loc)
		}
		s.LastRunAt = &now
	}

	s.NextRunAt = s.LastRunAt.Add(s.Duration())

	return s.NextRunAt
}

// // Duration returns interval between runs
func (s *Schedule) Duration() time.Duration {
	if s.period == 0 {
		switch s.Unit {
		case Seconds:
			s.period = time.Duration(s.Interval) * time.Second
		case Minutes:
			s.period = time.Duration(s.Interval) * time.Minute
		case Hours:
			s.period = time.Duration(s.Interval) * time.Hour
		case Days:
			s.period = time.Duration(s.Interval) * time.Hour * 24
		case Weeks:
			s.period = time.Duration(s.Interval) * time.Hour * 24 * 7
		}
	}
	return s.period
}
