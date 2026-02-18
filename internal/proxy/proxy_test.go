package proxy

import (
	"encoding/json"
	"testing"

	"github.com/coal/lobstertrap/internal/metadata"
)

func TestParseChatRequest(t *testing.T) {
	body := `{
		"model": "llama3",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Hello, how are you?"}
		]
	}`

	req, err := ParseChatRequest([]byte(body))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if req.Model != "llama3" {
		t.Errorf("expected model llama3, got %s", req.Model)
	}
	if len(req.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(req.Messages))
	}
	if req.Messages[1].Content != "Hello, how are you?" {
		t.Errorf("unexpected content: %s", req.Messages[1].Content)
	}
}

func TestExtractPromptText(t *testing.T) {
	req := &ChatCompletionRequest{
		Messages: []ChatMessage{
			{Role: "system", Content: "You are helpful."},
			{Role: "user", Content: "What is 2+2?"},
		},
	}

	text := ExtractPromptText(req)
	if text != "You are helpful.\nWhat is 2+2?" {
		t.Errorf("unexpected prompt text: %q", text)
	}
}

func TestMakeDenyResponse(t *testing.T) {
	resp := MakeDenyResponse("blocked", "test-model", nil)
	if len(resp.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(resp.Choices))
	}
	if resp.Choices[0].Message.Content != "blocked" {
		t.Errorf("unexpected content: %s", resp.Choices[0].Message.Content)
	}
	if resp.Model != "test-model" {
		t.Errorf("unexpected model: %s", resp.Model)
	}

	// Ensure it's valid JSON
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty JSON output")
	}
}

func TestParseChatResponse(t *testing.T) {
	body := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "llama3",
		"choices": [
			{
				"index": 0,
				"message": {"role": "assistant", "content": "Hello! I'm doing well."},
				"finish_reason": "stop"
			}
		]
	}`

	resp, err := ParseChatResponse([]byte(body))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	text := ExtractResponseText(resp)
	if text != "Hello! I'm doing well." {
		t.Errorf("unexpected response text: %q", text)
	}
}

func TestParseChatRequest_WithAgentGuard(t *testing.T) {
	body := `{
		"model": "llama3",
		"messages": [{"role": "user", "content": "hello"}],
		"_agentguard": {
			"declared_intent": "general",
			"declared_paths": ["/home/cole/notes.txt"],
			"agent_id": "my-agent-v1"
		}
	}`

	req, err := ParseChatRequest([]byte(body))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if req.AgentGuard == nil {
		t.Fatal("expected _agentguard to be parsed")
	}
	if req.AgentGuard.DeclaredIntent != "general" {
		t.Errorf("expected declared_intent general, got %s", req.AgentGuard.DeclaredIntent)
	}
	if req.AgentGuard.AgentID != "my-agent-v1" {
		t.Errorf("expected agent_id my-agent-v1, got %s", req.AgentGuard.AgentID)
	}
	if len(req.AgentGuard.DeclaredPaths) != 1 || req.AgentGuard.DeclaredPaths[0] != "/home/cole/notes.txt" {
		t.Errorf("unexpected declared_paths: %v", req.AgentGuard.DeclaredPaths)
	}
}

func TestParseChatRequest_WithoutAgentGuard(t *testing.T) {
	body := `{
		"model": "llama3",
		"messages": [{"role": "user", "content": "hello"}]
	}`

	req, err := ParseChatRequest([]byte(body))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if req.AgentGuard != nil {
		t.Errorf("expected nil _agentguard for standard request, got %+v", req.AgentGuard)
	}
}

func TestMakeDenyResponse_WithHeaders(t *testing.T) {
	headers := &metadata.ResponseHeaders{
		RequestID: "req-42",
		Verdict:   "DENY",
	}
	resp := MakeDenyResponse("blocked", "test-model", headers)

	if resp.AgentGuard == nil {
		t.Fatal("expected _agentguard in deny response")
	}
	if resp.AgentGuard.RequestID != "req-42" {
		t.Errorf("expected request_id req-42, got %s", resp.AgentGuard.RequestID)
	}
	if resp.AgentGuard.Verdict != "DENY" {
		t.Errorf("expected verdict DENY, got %s", resp.AgentGuard.Verdict)
	}

	// Ensure _agentguard appears in JSON output
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal raw: %v", err)
	}
	if _, ok := raw["_agentguard"]; !ok {
		t.Error("expected _agentguard key in JSON output")
	}
}

func TestInjectAgentGuardHeaders(t *testing.T) {
	backendResp := `{"id":"chatcmpl-123","object":"chat.completion","model":"llama3","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}]}`

	headers := &metadata.ResponseHeaders{
		RequestID: "req-1",
		Verdict:   "ALLOW",
	}

	injected, err := injectAgentGuardHeaders([]byte(backendResp), headers)
	if err != nil {
		t.Fatalf("injection failed: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(injected, &raw); err != nil {
		t.Fatalf("failed to unmarshal injected: %v", err)
	}

	// Original fields preserved
	if _, ok := raw["id"]; !ok {
		t.Error("original 'id' field missing after injection")
	}
	if _, ok := raw["choices"]; !ok {
		t.Error("original 'choices' field missing after injection")
	}

	// _agentguard injected
	agRaw, ok := raw["_agentguard"]
	if !ok {
		t.Fatal("_agentguard not found in injected response")
	}

	var rh metadata.ResponseHeaders
	if err := json.Unmarshal(agRaw, &rh); err != nil {
		t.Fatalf("failed to parse _agentguard: %v", err)
	}
	if rh.RequestID != "req-1" {
		t.Errorf("expected request_id req-1, got %s", rh.RequestID)
	}
	if rh.Verdict != "ALLOW" {
		t.Errorf("expected verdict ALLOW, got %s", rh.Verdict)
	}
}

func TestIsChatCompletionEndpoint(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/v1/chat/completions", true},
		{"/api/chat", true},
		{"/api/generate", true},
		{"/chat/completions", true},
		{"/v1/models", false},
		{"/health", false},
		{"/api/tags", false},
	}

	for _, tc := range tests {
		got := isChatCompletionEndpoint(tc.path)
		if got != tc.expected {
			t.Errorf("path %q: expected %v, got %v", tc.path, tc.expected, got)
		}
	}
}
