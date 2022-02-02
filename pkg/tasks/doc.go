// Package tasks is task scheduling package which lets you run Go functions
// periodically at pre-determined interval using a simple, human-friendly syntax.
/*
	scheduler := tasks.NewScheduler()

	// Do tasks with params
	tasks.NewTaskAtIntervals(1, Minutes).Do(taskWithParams, 1, "hello")

	// Do tasks without params
	tasks.NewTaskAtIntervals(30, Seconds).Do(task)
	tasks.NewTaskAtIntervals(5, Minutes).Do(task)
	tasks.NewTaskAtIntervals(8, Hours).Do(task)

	// Do tasks on specific weekday
	tasks.NewTaskOnWeekday(time.Monday, 23, 59).Do(task)

	// Do tasks daily
	tasks.NewTaskDaily(10,30).Do(task)

	// Parse from string format
	tasks.NewTask("16:18")
	tasks.NewTask("every 1 second")
	tasks.NewTask("every 61 minutes")
	tasks.NewTask("every day")
	tasks.NewTask("every day 11:15")
	tasks.NewTask("Monday")
	tasks.NewTask("Saturday 23:13")

	scheduler.Add(j)

	// Start the scheduler
	scheduler.Start()

	// Stop the scheduler
	scheduler.Stop()
*/
package tasks
