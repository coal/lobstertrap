package metadata

import (
	"testing"

	"github.com/coal/lobstertrap/internal/inspector"
)

func TestDetectMismatches_NilDeclared(t *testing.T) {
	detected := &inspector.PromptMetadata{IntentCategory: "general"}
	mismatches := DetectMismatches(nil, detected)
	if mismatches != nil {
		t.Errorf("expected nil mismatches for nil declared, got %v", mismatches)
	}
}

func TestDetectMismatches_NoMismatches(t *testing.T) {
	declared := &RequestHeaders{
		DeclaredIntent: "file_io",
		DeclaredPaths:  []string{"/home/cole/notes.txt"},
	}
	detected := &inspector.PromptMetadata{
		IntentCategory: "file_io",
		TargetPaths:    []string{"/home/cole/notes.txt"},
	}
	mismatches := DetectMismatches(declared, detected)
	if len(mismatches) != 0 {
		t.Errorf("expected no mismatches, got %d: %v", len(mismatches), mismatches)
	}
}

func TestDetectMismatches_IntentMismatch_Warning(t *testing.T) {
	declared := &RequestHeaders{DeclaredIntent: "general"}
	detected := &inspector.PromptMetadata{IntentCategory: "file_io"}

	mismatches := DetectMismatches(declared, detected)
	if len(mismatches) != 1 {
		t.Fatalf("expected 1 mismatch, got %d", len(mismatches))
	}
	if mismatches[0].Field != "intent" {
		t.Errorf("expected intent field, got %s", mismatches[0].Field)
	}
	if mismatches[0].Severity != "warning" {
		t.Errorf("expected warning severity, got %s", mismatches[0].Severity)
	}
}

func TestDetectMismatches_IntentMismatch_Critical(t *testing.T) {
	declared := &RequestHeaders{DeclaredIntent: "general"}
	detected := &inspector.PromptMetadata{IntentCategory: "credential_access"}

	mismatches := DetectMismatches(declared, detected)
	if len(mismatches) != 1 {
		t.Fatalf("expected 1 mismatch, got %d", len(mismatches))
	}
	if mismatches[0].Severity != "critical" {
		t.Errorf("expected critical severity for credential_access, got %s", mismatches[0].Severity)
	}
}

func TestDetectMismatches_UndeclaredPaths(t *testing.T) {
	declared := &RequestHeaders{
		DeclaredPaths: []string{"/home/cole/notes.txt"},
	}
	detected := &inspector.PromptMetadata{
		TargetPaths: []string{"/home/cole/notes.txt", "/etc/shadow"},
	}

	mismatches := DetectMismatches(declared, detected)
	if len(mismatches) != 1 {
		t.Fatalf("expected 1 mismatch, got %d", len(mismatches))
	}
	if mismatches[0].Field != "paths" {
		t.Errorf("expected paths field, got %s", mismatches[0].Field)
	}
}

func TestDetectMismatches_UndeclaredCommands(t *testing.T) {
	declared := &RequestHeaders{}
	detected := &inspector.PromptMetadata{
		TargetCommands: []string{"rm -rf /"},
	}

	mismatches := DetectMismatches(declared, detected)
	found := false
	for _, m := range mismatches {
		if m.Field == "commands" {
			found = true
			if m.Severity != "critical" {
				t.Errorf("expected critical severity for commands, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Error("expected commands mismatch")
	}
}

func TestDetectMismatches_UndeclaredDomains(t *testing.T) {
	declared := &RequestHeaders{
		DeclaredDomains: []string{"example.com"},
	}
	detected := &inspector.PromptMetadata{
		TargetDomains: []string{"example.com", "evil.com"},
	}

	mismatches := DetectMismatches(declared, detected)
	found := false
	for _, m := range mismatches {
		if m.Field == "domains" {
			found = true
		}
	}
	if !found {
		t.Error("expected domains mismatch")
	}
}

func TestDetectMismatches_MultipleMismatches(t *testing.T) {
	declared := &RequestHeaders{
		DeclaredIntent: "general",
	}
	detected := &inspector.PromptMetadata{
		IntentCategory: "system",
		TargetPaths:    []string{"/etc/passwd"},
		TargetCommands: []string{"cat /etc/passwd"},
	}

	mismatches := DetectMismatches(declared, detected)
	if len(mismatches) < 3 {
		t.Errorf("expected at least 3 mismatches, got %d", len(mismatches))
	}
}
