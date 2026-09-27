package restserver

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBroadcastConcurrentRegistration(t *testing.T) {
	t.Parallel()

	server := &HTTPServer{evtHandlers: make(map[ServerEvent][]ServerEventFunc)}
	var calls atomic.Int64
	server.OnEvent(ServerStartedEvent, func(ServerEvent) { calls.Add(1) })

	const iterations = 100
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for range iterations {
			server.OnEvent(ServerStartedEvent, func(ServerEvent) { calls.Add(1) })
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for range iterations {
			server.broadcast(ServerStartedEvent)
		}
	}()
	close(start)
	workers.Wait()
	assert.GreaterOrEqual(t, calls.Load(), int64(iterations))
}
