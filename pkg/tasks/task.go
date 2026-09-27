package tasks

import (
	"cmp"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

// TimeUnit is the unit of a Schedule interval (Seconds, Minutes, ...).
type TimeUnit uint

// TimeNow is the clock used by the package to compute and compare run times.
// It is a process-global variable intended to be overridden in tests.
var TimeNow = time.Now

const (
	// Never is the zero unit; ParseSchedule rejects it. A Schedule with Unit
	// Never has a zero Duration and would be due on every tick.
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

// Task is a scheduled unit of work: a Schedule plus a callback bound with Do.
// Create one with New, NewTask, NewTaskAtIntervals, NewTaskOnWeekday or
// NewTaskDaily, bind the callback with Do, then hand it to Scheduler.Add.
// Task methods synchronize run state. Schedule returns a snapshot; use
// SetNextRun or UpdateSchedule to change a task's schedule.
type Task interface {
	// ID returns the task ID: the WithID option value or a generated UUIDv7.
	ID() string
	// Name returns "<taskName>@<callback function name>" as set by Do;
	// empty before Do is called.
	Name() string
	// RunCount returns how many times Run has started the callback.
	RunCount() uint32
	// Schedule returns a snapshot of the current schedule and run state.
	Schedule() *Schedule
	// UpdateSchedule replaces the schedule with one parsed from format
	// (see ParseSchedule); the next run is recomputed on the next Run.
	UpdateSchedule(format string) error
	// ShouldRun reports whether the task is not running and NextRunAt has passed.
	ShouldRun() bool
	// Run executes the callback if the run lock can be acquired within the
	// run timeout, then recomputes NextRunAt and returns true. It returns
	// false without running if the task is already running. Callback panics
	// are recovered and logged.
	Run() bool
	// SetNextRun forces the next run to TimeNow()+after.
	SetNextRun(time.Duration) Task
	// Do binds the callback and its arguments and computes the first NextRunAt.
	// It panics if task is not a function or the number of params does not
	// match its arity; argument types are only checked when the callback is
	// invoked (a mismatch is then recovered and logged as an error).
	Do(taskName string, task any, params ...any) Task
	// IsRunning reports whether the callback is currently executing.
	IsRunning() bool
	// SetPublisher sets the Publisher notified before and after each run.
	SetPublisher(Publisher) Task
	// Publish sends the task to its Publisher, if any.
	Publish()
}

// Schedule describes when a task runs. Fields are exported for inspection
// (e.g. by a Publisher). Task.Schedule returns a snapshot of these fields.
type Schedule struct {
	// Format is the original string given to ParseSchedule, if any.
	Format string
	// Interval is the number of Unit between runs.
	Interval uint64
	// Unit is the time unit of Interval.
	Unit TimeUnit
	// StartDay is the weekday for Weeks schedules (ignored otherwise).
	StartDay time.Weekday
	// LastRunAt is when the task last started; nil until first run or
	// until an "hh:mm" anchor is applied.
	LastRunAt *time.Time
	// NextRunAt is when the task is next due.
	NextRunAt time.Time
	// RunCount is the number of runs; updated atomically by Run.
	RunCount uint32
	// period caches Duration(); it is computed once and never invalidated.
	period time.Duration
}

// Equal reports whether the two schedules have the same Interval, Unit,
// StartDay and Format; run state is ignored.
func (s *Schedule) Equal(other *Schedule) bool {
	return s.Interval == other.Interval &&
		s.Unit == other.Unit &&
		s.StartDay == other.StartDay &&
		s.Format == other.Format
}

// GetLastRun returns LastRunAt, or nil if the task has never actually run
// (RunCount == 0), even when LastRunAt was set as a schedule anchor.
func (s *Schedule) GetLastRun() *time.Time {
	if s.LastRunAt == nil || s.RunCount == 0 {
		return nil
	}
	return s.LastRunAt
}

// task describes a task schedule
type task struct {
	state sync.RWMutex
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

// DefaultRunTimeoutInterval is how long Run waits for the task's run lock
// before reporting "already running" (override with WithRunTimeout).
const DefaultRunTimeoutInterval = time.Second

// NewTaskAtIntervals creates a task that runs every interval*unit, starting
// one interval after Do is called. An interval of 0 yields a zero Duration
// and the task becomes due on every tick.
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

// NewTaskOnWeekday creates a weekly task that runs on startDay at hour:minute
// in the package location. It panics if hour or minute is out of range.
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

// NewTaskDaily creates a task that runs every day at hour:minute in the
// package location. It panics if hour or minute is out of range.
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

// NewTask creates a task from a schedule string (see ParseSchedule), e.g.
// "every 5 minutes", "every day 11:15", "16:18", "monday", "saturday 23:13".
// It returns an error for an invalid format.
func NewTask(format string, ops ...Option) (Task, error) {
	s, err := ParseSchedule(format)
	if err != nil {
		return nil, err
	}

	return New(s, ops...), nil
}

// New copies a Schedule into a Task. Later changes to the input do not affect
// the task. Use WithID, WithRunTimeout and WithPublisher to customize; the
// callback must still be bound with Do.
func New(s *Schedule, ops ...Option) Task {
	dops := options{
		id:         uuid.NewV7().String(),
		runTimeout: DefaultRunTimeoutInterval,
	}
	for _, op := range ops {
		op.apply(&dops)
	}

	dops.id = cmp.Or(dops.id, uuid.NewV7().String())
	j := &task{
		id:         dops.id,
		schedule:   cloneSchedule(s),
		runLock:    make(chan struct{}, 1),
		runTimeout: dops.runTimeout,
		publisher:  dops.publisher,
	}

	return j
}

// SetPublisher sets the Publisher notified on status changes.
func (j *task) SetPublisher(pub Publisher) Task {
	j.state.Lock()
	j.publisher = pub
	j.state.Unlock()
	return j
}

// Publish sends the task to its Publisher, if one is set.
func (j *task) Publish() {
	j.state.RLock()
	pub := j.publisher
	j.state.RUnlock()
	if pub != nil {
		pub.Publish(j)
	}
}

// UpdateSchedule replaces the schedule with one parsed from format.
func (j *task) UpdateSchedule(format string) error {
	s, err := ParseSchedule(format)
	if err != nil {
		return err
	}
	j.state.Lock()
	j.schedule = s
	j.state.Unlock()
	return nil
}

// SetNextRun forces the next run to TimeNow()+after.
func (j *task) SetNextRun(after time.Duration) Task {
	j.state.Lock()
	j.schedule.NextRunAt = TimeNow().Add(after)
	j.state.Unlock()
	return j
}

// ID returns the task ID.
func (j *task) ID() string {
	return j.id
}

// Name returns "<taskName>@<function>" as set by Do.
func (j *task) Name() string {
	j.state.RLock()
	defer j.state.RUnlock()
	return j.name
}

// Schedule returns a snapshot of the current schedule.
func (j *task) Schedule() *Schedule {
	j.state.RLock()
	defer j.state.RUnlock()
	return cloneSchedule(j.schedule)
}

func cloneSchedule(s *Schedule) *Schedule {
	if s == nil {
		return nil
	}
	copy := *s
	if s.LastRunAt != nil {
		lastRun := *s.LastRunAt
		copy.LastRunAt = &lastRun
	}
	return &copy
}

// RunCount returns the number of runs started so far.
func (j *task) RunCount() uint32 {
	j.state.RLock()
	defer j.state.RUnlock()
	return atomic.LoadUint32(&j.schedule.RunCount)
}

// ShouldRun reports whether the task is idle and due.
func (j *task) ShouldRun() bool {
	j.state.RLock()
	defer j.state.RUnlock()
	return !j.running && j.schedule.ShouldRun()
}

// IsRunning reports whether the callback is executing.
func (j *task) IsRunning() bool {
	j.state.RLock()
	defer j.state.RUnlock()
	return j.running
}

// Do binds the callback and parameters and schedules the first run.
// It panics if taskFunc is not a function or len(params) differs from its arity.
func (j *task) Do(taskName string, taskFunc any, params ...any) Task {
	typ := reflect.TypeOf(taskFunc)
	if typ.Kind() != reflect.Func {
		logger.Panic("only function can be scheduled into the task queue")
	}

	callback := reflect.ValueOf(taskFunc)
	if len(params) != callback.Type().NumIn() {
		logger.Panicf("the number of parameters does not match the function")
	}
	values := make([]reflect.Value, len(params))
	for k, param := range params {
		values[k] = reflect.ValueOf(param)
	}

	j.state.Lock()
	j.name = fmt.Sprintf("%s@%s", taskName, filepath.Base(getFunctionName(taskFunc)))
	j.callback = callback
	j.params = values
	//schedule the next run
	j.schedule.UpdateNextRun()
	j.state.Unlock()

	return j
}

func (s *Schedule) at(hour, minutes int) *Schedule {
	now := TimeNow()
	y, m, d := now.Date()

	lastRun := time.Date(y, m, d, hour, minutes, 0, 0, loc)

	switch s.Unit {
	case Days:
		if !now.After(lastRun) {
			// remove 1 day
			lastRun = lastRun.UTC().AddDate(0, 0, -1).Local()
		}
	case Weeks:
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
func getFunctionName(fn any) string {
	return runtime.FuncForPC(reflect.ValueOf((fn)).Pointer()).Name()
}

// Run executes the callback once if the run lock is acquired within the run
// timeout, publishes before and after, recomputes NextRunAt and returns true.
// It returns false if the task was still running when the timeout elapsed.
func (j *task) Run() bool {
	timeout := j.runTimeout
	if timeout == 0 {
		timeout = DefaultRunTimeoutInterval
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case j.runLock <- struct{}{}:
		now := TimeNow()
		j.state.Lock()
		j.schedule.LastRunAt = &now
		j.running = true
		count := atomic.AddUint32(&j.schedule.RunCount, 1)
		callback := j.callback
		params := j.params
		j.state.Unlock()

		logger.KV(xlog.DEBUG,
			"status", "running",
			"run_count", count,
			"started_at", now,
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
			callback.Call(params)
		}()

		j.state.Lock()
		j.running = false
		j.schedule.UpdateNextRun()
		j.state.Unlock()
		j.Publish()

		<-j.runLock
		return true
	case <-timer.C:
	}

	j.state.RLock()
	count := j.schedule.RunCount
	lastRun := j.schedule.LastRunAt
	j.state.RUnlock()
	logger.KV(xlog.DEBUG,
		"status", "already_running",
		"run_count", count,
		"started_at", lastRun,
		"task", j.Name())

	return false
}

func parseTimeFormat(t string) (hour, minutes int, err error) {
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
	minutes, err = strconv.Atoi(ts[1])
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	if hour < 0 || hour > 23 || minutes < 0 || minutes > 59 {
		err = errors.WithStack(errTimeFormat)
		return
	}
	return
}

// ParseSchedule parses a case-insensitive, space-separated schedule string:
//
//	[every] [N] (second|minute|hour|day|week)[s] [hh:mm]
//	<weekday> [hh:mm]
//
// "hh:mm" alone means daily at that time; with a weekday it means weekly.
// It returns an error when the format is ambiguous or the unit is missing.
func ParseSchedule(format string) (*Schedule, error) {
	var errTimeFormat = errors.Errorf("task format not valid: %q", format)

	s := &Schedule{
		Format:    format,
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
				hour, minutes, err := parseTimeFormat(t)
				if err != nil {
					return nil, errors.WithStack(errTimeFormat)
				}
				if s.Unit == Never {
					s.Unit = Days
				} else if s.Unit != Days && s.Unit != Weeks {
					return nil, errors.WithStack(errTimeFormat)
				}
				s.at(hour, minutes)
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

// ShouldRun reports whether TimeNow() is past NextRunAt.
func (s *Schedule) ShouldRun() bool {
	return TimeNow().After(s.NextRunAt)
}

// UpdateNextRun sets NextRunAt to LastRunAt+Duration and returns it. When
// LastRunAt is nil it is first anchored to now (or, for Weeks, to midnight of
// the most recent StartDay).
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

// Duration returns Interval*Unit as a time.Duration (0 for Never). The value
// is cached on first call, so later changes to Interval/Unit are not reflected.
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
