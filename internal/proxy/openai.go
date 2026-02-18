package proxy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/coal/lobstertrap/internal/metadata"
)

// ChatMessage represents a single message in the OpenAI chat format.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionRequest is the OpenAI chat completions request format.
type ChatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	Temperature *float64      `json:"temperature,omitempty"`
	MaxTokens   *int          `json:"max_tokens,omitempty"`
	Stream      bool          `json:"stream,omitempty"`
	// Agent Guard metadata headers (optional, from _agentguard field)
	AgentGuard *metadata.RequestHeaders `json:"_agentguard,omitempty"`
	// Preserve other fields
	Extra map[string]any `json:"-"`
}

// ChatChoice represents a single choice in the response.
type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// ChatCompletionResponse is the OpenAI chat completions response format.
type ChatCompletionResponse struct {
	ID         string                    `json:"id"`
	Object     string                    `json:"object"`
	Created    int64                     `json:"created"`
	Model      string                    `json:"model"`
	Choices    []ChatChoice              `json:"choices"`
	Usage      *Usage                    `json:"usage,omitempty"`
	AgentGuard *metadata.ResponseHeaders `json:"_agentguard,omitempty"`
}

// Usage tracks token usage.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ParseChatRequest parses an OpenAI chat completion request from JSON bytes.
func ParseChatRequest(data []byte) (*ChatCompletionRequest, error) {
	var req ChatCompletionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parsing chat request: %w", err)
	}
	return &req, nil
}

// ParseChatResponse parses an OpenAI chat completion response from JSON bytes.
func ParseChatResponse(data []byte) (*ChatCompletionResponse, error) {
	var resp ChatCompletionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing chat response: %w", err)
	}
	return &resp, nil
}

// ExtractPromptText extracts the full prompt text from all messages.
func ExtractPromptText(req *ChatCompletionRequest) string {
	var parts []string
	for _, msg := range req.Messages {
		parts = append(parts, msg.Content)
	}
	return strings.Join(parts, "\n")
}

// ExtractResponseText extracts the text from the first choice of a response.
func ExtractResponseText(resp *ChatCompletionResponse) string {
	if len(resp.Choices) == 0 {
		return ""
	}
	return resp.Choices[0].Message.Content
}

// MakeDenyResponse creates a chat completion response with a deny message
// and optional Agent Guard response headers.
func MakeDenyResponse(message string, model string, headers *metadata.ResponseHeaders) *ChatCompletionResponse {
	return &ChatCompletionResponse{
		ID:         "agentguard-deny",
		Object:     "chat.completion",
		Model:      model,
		AgentGuard: headers,
		Choices: []ChatChoice{
			{
				Index: 0,
				Message: ChatMessage{
					Role:    "assistant",
					Content: message,
				},
				FinishReason: "stop",
			},
		},
	}
}

// injectAgentGuardHeaders injects _agentguard response headers into raw
// backend response JSON without disturbing any other fields.
func injectAgentGuardHeaders(respBody []byte, headers *metadata.ResponseHeaders) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, err
	}

	headerBytes, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}
	raw["_agentguard"] = headerBytes

	return json.Marshal(raw)
}
