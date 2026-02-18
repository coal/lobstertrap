package dashboard

import "sync"

const defaultBufferSize = 1000

// RingBuffer is a thread-safe circular buffer of DashboardEvents.
type RingBuffer struct {
	mu    sync.RWMutex
	items []*DashboardEvent
	head  int
	count int
	cap   int
}

// NewRingBuffer creates a ring buffer with the given capacity.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = defaultBufferSize
	}
	return &RingBuffer{
		items: make([]*DashboardEvent, capacity),
		cap:   capacity,
	}
}

// Add inserts an event into the buffer, overwriting the oldest if full.
func (rb *RingBuffer) Add(event *DashboardEvent) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	idx := (rb.head + rb.count) % rb.cap
	if rb.count == rb.cap {
		// Buffer is full, overwrite oldest
		rb.items[rb.head] = event
		rb.head = (rb.head + 1) % rb.cap
	} else {
		rb.items[idx] = event
		rb.count++
	}
}

// All returns all events in chronological order (oldest first).
func (rb *RingBuffer) All() []*DashboardEvent {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([]*DashboardEvent, rb.count)
	for i := 0; i < rb.count; i++ {
		result[i] = rb.items[(rb.head+i)%rb.cap]
	}
	return result
}

// Len returns the number of events in the buffer.
func (rb *RingBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}
