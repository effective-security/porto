package tasks

import (
	"slices"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "tasks")

// DefaultTickerInterval is the upper bound for the scheduler tick when
// WithTickerInterval is not given; Start lowers it to 1/10 of the shortest
// task interval if that is smaller.
const DefaultTickerInterval = time.Second

// loc is the time location used to compute daily/weekly run times;
// defaults to time.Local and is changed by SetGlobalLocation.
var loc = time.Local

// SetGlobalLocation sets the process-global time location used when computing
// daily and weekly run times (NewTaskDaily, NewTaskOnWeekday, "hh:mm" formats).
// It is not synchronized; call it before creating tasks.
func SetGlobalLocation(newLocation *time.Location) {
	loc = newLocation
}

// Scheduler owns a set of tasks and a ticker goroutine that starts due tasks.
// Its methods are safe for concurrent use.
type Scheduler interface {
	// SetPublisher sets the publisher on the scheduler and on every task
	// already added; tasks added later inherit it in Add.
	SetPublisher(Publisher) Scheduler
	// Add appends a task to the pool. It may be called while the scheduler
	// is running; the task is picked up on the next tick.
	Add(Task) Scheduler
	// Get returns the task with the given ID, or nil if not found.
	Get(id string) Task
	// List returns a snapshot of the registered task slice. Changes to the
	// returned slice do not change scheduler membership.
	List() []Task
	// Clear removes all tasks from the pool. Tasks already started keep running.
	Clear()
	// Count returns the number of registered tasks.
	Count() int
	// IsRunning reports whether Start has been called and Stop has not yet
	// taken effect.
	IsRunning() bool
	// Start publishes every task and spawns the ticker goroutine.
	// It returns an error if the scheduler is already running.
	Start() error
	// Stop signals the ticker goroutine to exit. It does not wait for the
	// goroutine or for in-flight tasks. Repeated calls succeed.
	Stop() error
	// Publish calls Publish on every registered task.
	Publish()
}

// Publisher receives task status notifications: Scheduler.Start publishes
// every task once, and each task publishes itself right before and right
// after every run (see Task.IsRunning). Implementations must be safe for
// concurrent use because tasks run in their own goroutines.
type Publisher interface {
	// Publish is called with the task whose status changed.
	Publish(task Task)
}

// scheduler provides a task scheduler functionality
type scheduler struct {
	dops options

	tasks   []Task
	running bool
	quit    chan struct{}
	lock    sync.RWMutex
}

// NewScheduler creates a stopped scheduler. Only WithTickerInterval and
// WithPublisher are meaningful here; task-level options are ignored.
func NewScheduler(ops ...Option) Scheduler {
	s := &scheduler{
		tasks:   []Task{},
		running: false,
	}

	for _, op := range ops {
		op.apply(&s.dops)
	}

	return s
}

// SetPublisher sets the publisher for the scheduler and all registered tasks.
func (s *scheduler) SetPublisher(pub Publisher) Scheduler {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.dops.publisher = pub
	for i := range s.tasks {
		s.tasks[i].SetPublisher(pub)
	}
	return s
}

// Publish calls Publish on every registered task.
func (s *scheduler) Publish() {
	for _, task := range s.List() {
		task.Publish()
	}
}

// Count returns the number of registered tasks
func (s *scheduler) Count() int {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return len(s.tasks)
}

// Get the current runnable tasks, which shouldRun is True
func (s *scheduler) getRunnableTasks() []Task {
	tasks := s.List()
	type scheduledTask struct {
		task Task
		next time.Time
	}
	scheduled := make([]scheduledTask, len(tasks))
	for i, task := range tasks {
		scheduled[i] = scheduledTask{
			task: task,
			next: task.Schedule().NextRunAt,
		}
	}
	runnable := []Task{}
	slices.SortFunc(scheduled, func(a, b scheduledTask) int {
		return a.next.Compare(b.next)
	})
	for _, entry := range scheduled {
		if entry.task.ShouldRun() {
			runnable = append(runnable, entry.task)
		}
	}
	return runnable
}

// List returns all registered tasks
func (s *scheduler) List() []Task {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return slices.Clone(s.tasks)
}

// Add adds a task to a pool of scheduled tasks
func (s *scheduler) Add(j Task) Scheduler {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.dops.publisher != nil {
		j.SetPublisher(s.dops.publisher)
	}

	s.tasks = append(s.tasks, j)
	return s
}

// Get returns the task with the given ID, or nil if not found.
func (s *scheduler) Get(id string) Task {
	s.lock.RLock()
	defer s.lock.RUnlock()

	for _, t := range s.tasks {
		if t.ID() == id {
			return t
		}
	}
	return nil
}

// runPending will run all the tasks that are scheduled to run.
func (s *scheduler) runPending() {
	for _, task := range s.getRunnableTasks() {
		logger.KV(xlog.DEBUG, "status", "pending_run", "task", task.Name())
		go task.Run()
	}
}

// Clear will delete all scheduled tasks
func (s *scheduler) Clear() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.tasks = []Task{}
}

// IsRunning reports whether the ticker goroutine is active.
func (s *scheduler) IsRunning() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.running
}

// Start publishes every task, computes the tick interval and spawns the
// ticker goroutine. It returns an error if already running.
func (s *scheduler) Start() error {
	s.lock.Lock()
	if s.running {
		s.lock.Unlock()
		return errors.Errorf("schedule already started")
	}
	s.running = true
	s.quit = make(chan struct{})
	quit := s.quit
	tasks := slices.Clone(s.tasks)

	interval := s.dops.tickerInterval
	if interval == 0 {
		// if not specified, then find a reasonable interval to schedule
		interval = DefaultTickerInterval
		for _, t := range tasks {
			in := t.Schedule().Duration()
			if in < interval {
				interval = in / 10 // use 1/10 of a task schedule interval
			}
		}
	}

	if interval == 0 {
		interval = DefaultTickerInterval
	}

	logger.KV(xlog.DEBUG,
		"tasks", len(tasks),
		"schedule_interval", interval,
	)
	s.lock.Unlock()

	for _, j := range tasks {
		j.Publish()
	}

	s.lock.Lock()
	if !s.running || s.quit != quit {
		s.lock.Unlock()
		return nil
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.runPending()
			case <-quit:
				return
			}
		}
	}()
	s.lock.Unlock()

	return nil
}

// Stop signals the ticker goroutine to exit; it does not wait for it or for
// in-flight tasks. Repeated calls succeed.
func (s *scheduler) Stop() error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.running {
		return nil
	}

	s.running = false
	close(s.quit)

	return nil
}

// Option configures a Scheduler (NewScheduler) or a Task (New, NewTask*).
// Options not applicable to the receiver are silently ignored: WithTickerInterval
// applies only to schedulers, WithID and WithRunTimeout only to tasks, and
// WithPublisher to both.
type Option interface {
	apply(*options)
}

type options struct {
	tickerInterval time.Duration
	id             string
	runTimeout     time.Duration
	publisher      Publisher
}

type funcOption struct {
	f func(*options)
}

func (fo *funcOption) apply(o *options) {
	fo.f(o)
}

func newFuncOption(f func(*options)) *funcOption {
	return &funcOption{
		f: f,
	}
}

// WithTickerInterval sets a fixed scheduler tick interval instead of the
// computed default (see DefaultTickerInterval). Scheduler-only.
func WithTickerInterval(tickerInterval time.Duration) Option {
	return newFuncOption(func(o *options) {
		o.tickerInterval = tickerInterval
	})
}

// WithID sets the task ID instead of the generated UUIDv7. Task-only.
func WithID(id string) Option {
	return newFuncOption(func(o *options) {
		o.id = id
	})
}

// WithRunTimeout sets how long Task.Run waits to acquire the task's run lock
// before giving up (default DefaultRunTimeoutInterval). Task-only.
func WithRunTimeout(runTimeout time.Duration) Option {
	return newFuncOption(func(o *options) {
		o.runTimeout = runTimeout
	})
}

// WithPublisher sets the Publisher for a scheduler (propagated to its tasks)
// or for an individual task.
func WithPublisher(publisher Publisher) Option {
	return newFuncOption(func(o *options) {
		o.publisher = publisher
	})
}
