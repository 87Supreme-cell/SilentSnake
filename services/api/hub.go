package main

import (
	"sync"
	"sync/atomic"
)

// Hub fans live-log entries out to stream subscribers. A slow subscriber never blocks the
// capture reader: entries it can't take are counted as dropped for that subscriber.
type Hub struct {
	mu   sync.Mutex
	subs map[*Sub]struct{}
}

type Sub struct {
	C       chan LogEntry
	Dropped atomic.Uint64
}

func NewHub() *Hub { return &Hub{subs: map[*Sub]struct{}{}} }

func (h *Hub) Subscribe() *Sub {
	s := &Sub{C: make(chan LogEntry, 256)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

func (h *Hub) Unsubscribe(s *Sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

func (h *Hub) Publish(e LogEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		select {
		case s.C <- e:
		default:
			s.Dropped.Add(1)
		}
	}
}
