package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Entry represents a single audit log entry.
type Entry struct {
	Timestamp       time.Time `json:"timestamp"`
	RequestID       string    `json:"request_id"`
	Direction       string    `json:"direction"` // "ingress" or "egress"
	Action          string    `json:"action"`
	RuleName        string    `json:"rule_name,omitempty"`
	DenyMessage     string    `json:"deny_message,omitempty"`
	Metadata        any       `json:"metadata,omitempty"`
	Prompt          string    `json:"prompt,omitempty"`
	TokenCount      int       `json:"token_count,omitempty"`
	DeclaredHeaders any       `json:"declared_headers,omitempty"`
	Mismatches      any       `json:"mismatches,omitempty"`
	AgentID         string    `json:"agent_id,omitempty"`
}

// Logger writes JSON-line audit log entries.
type Logger struct {
	mu     sync.Mutex
	writer io.Writer
	enc    *json.Encoder
}

// NewLogger creates a new audit logger writing to the given writer.
func NewLogger(w io.Writer) *Logger {
	return &Logger{
		writer: w,
		enc:    json.NewEncoder(w),
	}
}

// NewFileLogger creates a logger that writes to a file at the given path.
// Creates the file if it doesn't exist, appends if it does.
func NewFileLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return NewLogger(f), nil
}

// NewStderrLogger creates a logger that writes to stderr.
func NewStderrLogger() *Logger {
	return NewLogger(os.Stderr)
}

// Log writes a single audit entry as a JSON line.
func (l *Logger) Log(entry Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(entry)
}

// NopLogger returns a logger that discards all entries.
func NopLogger() *Logger {
	return NewLogger(io.Discard)
}
