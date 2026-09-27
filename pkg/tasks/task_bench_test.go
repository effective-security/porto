package tasks

import "testing"

func BenchmarkTaskRun(b *testing.B) {
	task := NewTaskAtIntervals(0, Seconds).Do("benchmark", func() {})
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		task.Run()
	}
}
