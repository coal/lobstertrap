package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"

	"github.com/coal/lobstertrap/internal/pipeline"
	"github.com/coal/lobstertrap/internal/policy"
)

var eventCounter atomic.Uint64

// Hub manages WebSocket clients, event broadcasting, and stats.
type Hub struct {
	events *RingBuffer
	stats  *Stats
	policy *policy.Policy

	mu      sync.RWMutex
	clients map[*websocket.Conn]struct{}
}

// NewHub creates a new dashboard hub.
func NewHub(pol *policy.Policy) *Hub {
	return &Hub{
		events:  NewRingBuffer(defaultBufferSize),
		stats:   NewStats(),
		policy:  pol,
		clients: make(map[*websocket.Conn]struct{}),
	}
}

// OnEvent is the observer callback to register with the pipeline.
func (h *Hub) OnEvent(pe pipeline.PipelineEvent) {
	event := &DashboardEvent{
		ID:            fmt.Sprintf("evt-%d", eventCounter.Add(1)),
		PipelineEvent: pe,
	}

	h.events.Add(event)
	h.stats.Record(event)

	msg := WSMessage{Type: "event", Payload: event}
	h.broadcast(msg)
}

// Register adds a WebSocket client and sends it the initial state.
func (h *Hub) Register(conn *websocket.Conn) {
	h.mu.Lock()
	h.clients[conn] = struct{}{}
	h.mu.Unlock()

	initial := WSMessage{
		Type: "initial_state",
		Payload: InitialState{
			Events: h.events.All(),
			Stats:  h.stats.Snapshot(),
			Policy: h.policy,
		},
	}

	data, err := json.Marshal(initial)
	if err != nil {
		return
	}
	conn.Write(context.Background(), websocket.MessageText, data)
}

// Unregister removes a WebSocket client.
func (h *Hub) Unregister(conn *websocket.Conn) {
	h.mu.Lock()
	delete(h.clients, conn)
	h.mu.Unlock()
}

// broadcast sends a message to all connected clients.
func (h *Hub) broadcast(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.mu.RLock()
	clients := make([]*websocket.Conn, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		err := c.Write(context.Background(), websocket.MessageText, data)
		if err != nil {
			h.Unregister(c)
		}
	}
}

// StartStatsBroadcast pushes stats snapshots to all clients every interval.
func (h *Hub) StartStatsBroadcast(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			msg := WSMessage{
				Type:    "stats_update",
				Payload: h.stats.Snapshot(),
			}
			h.broadcast(msg)
		}
	}
}

// Events returns the ring buffer (for API handlers).
func (h *Hub) Events() *RingBuffer {
	return h.events
}

// StatsSnapshot returns a snapshot of accumulated stats.
func (h *Hub) StatsSnapshot() *StatsSnapshot {
	return h.stats.Snapshot()
}

// Policy returns the loaded policy.
func (h *Hub) PolicyConfig() *policy.Policy {
	return h.policy
}
