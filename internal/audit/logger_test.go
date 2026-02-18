package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf)

	err := logger.Log(Entry{
		RequestID: "test-1",
		Direction: "ingress",
		Action:    "DENY",
		RuleName:  "block_injection",
		Metadata:  map[string]any{"risk_score": 0.8},
	})
	if err != nil {
		t.Fatalf("failed to log: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test-1") {
		t.Error("expected request_id in output")
	}
	if !strings.Contains(output, "DENY") {
		t.Error("expected action in output")
	}

	// Verify it's valid JSON
	var entry Entry
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if entry.RequestID != "test-1" {
		t.Errorf("expected request_id test-1, got %s", entry.RequestID)
	}
}

func TestLogger_TimestampAutoFill(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf)

	before := time.Now().UTC()
	logger.Log(Entry{RequestID: "ts-test", Direction: "ingress", Action: "ALLOW"})
	after := time.Now().UTC()

	var entry Entry
	json.Unmarshal(buf.Bytes(), &entry)

	if entry.Timestamp.Before(before) || entry.Timestamp.After(after) {
		t.Error("auto-filled timestamp is out of range")
	}
}

func TestNopLogger(t *testing.T) {
	logger := NopLogger()
	err := logger.Log(Entry{RequestID: "nop", Direction: "ingress", Action: "ALLOW"})
	if err != nil {
		t.Errorf("nop logger should not error: %v", err)
	}
}
