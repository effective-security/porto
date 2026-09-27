// Package tasks is an in-process, cron-like scheduler that runs Go functions
// periodically using a small, human-friendly schedule syntax.
//
// A Task pairs a Schedule (interval, weekday, or daily time) with a callback
// bound via Do. A Scheduler owns a set of tasks and a single ticker goroutine
// that, on every tick, starts every task whose NextRunAt has passed in its own
// goroutine. A task never overlaps with itself: Run acquires a per-task lock and
// gives up (returning false) if the lock cannot be acquired within the task's
// run timeout. Panics raised by a callback are recovered and logged, and the
// task is rescheduled.
//
// Schedule formats accepted by NewTask and ParseSchedule (case-insensitive):
//
//	"every 1 second"      "every 61 minutes"     "every 2 hours"
//	"every day"           "every day 11:15"      "16:18"        (daily at 16:18)
//	"monday"              "saturday 23:13"       (weekly on that day)
//
// Usage:
//
//	s := tasks.NewScheduler(tasks.WithTickerInterval(time.Second))
//
//	s.Add(tasks.NewTaskAtIntervals(30, tasks.Seconds).Do("cleanup", cleanup))
//	s.Add(tasks.NewTaskAtIntervals(1, tasks.Minutes).Do("report", report, 1, "hello"))
//	s.Add(tasks.NewTaskOnWeekday(time.Monday, 23, 59).Do("weekly", weekly))
//	s.Add(tasks.NewTaskDaily(10, 30).Do("daily", daily))
//
//	t, err := tasks.NewTask("every day 11:15", tasks.WithID("nightly"))
//	if err != nil {
//		return err
//	}
//	s.Add(t.Do("nightly", nightly))
//
//	if err := s.Start(); err != nil { // spawns the ticker goroutine
//		return err
//	}
//	defer s.Stop() // signals the ticker to exit; does not wait for running tasks
//
// Scheduler.List returns a copy of the task slice, and Task.Schedule returns
// a snapshot of schedule state. New copies its input Schedule. Use Add/Clear
// and SetNextRun/UpdateSchedule to change live state. Stop is idempotent, and a
// stopped scheduler may be started again.
//
// The constructors NewTaskOnWeekday, NewTaskDaily and Task.Do panic on invalid
// input (out-of-range time, non-function callback, wrong parameter count);
// NewTask and ParseSchedule return an error for an invalid format string.
//
// Package-level state: TimeNow (the clock, overridable in tests) and the time
// location set by SetGlobalLocation are process-global and not synchronized.
package tasks
