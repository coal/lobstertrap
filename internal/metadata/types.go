package metadata

import (
	"github.com/coal/lobstertrap/internal/inspector"
	"github.com/coal/lobstertrap/internal/policy"
)

// RequestHeaders are optional agent-declared metadata sent in the _lobstertrap
// field of a chat completion request. Like packet headers in network DPI,
// they let the agent declare its intent so Lobster Trap can verify the claim
// against its own DPI extraction.
type RequestHeaders struct {
	DeclaredIntent   string   `json:"declared_intent,omitempty"`
	DeclaredPaths    []string `json:"declared_paths,omitempty"`
	DeclaredCommands []string `json:"declared_commands,omitempty"`
	DeclaredDomains  []string `json:"declared_domains,omitempty"`
	AgentID          string   `json:"agent_id,omitempty"`
}

// ResponseHeaders are embedded in every chat completion response under
// the _lobstertrap field. They carry the full inspection report back to
// the agent so it can see exactly what Lobster Trap detected and decided.
type ResponseHeaders struct {
	RequestID string        `json:"request_id"`
	Verdict   string        `json:"verdict"` // ALLOW, DENY, HUMAN_REVIEW
	Ingress   *IngressReport `json:"ingress,omitempty"`
	Egress    *EgressReport  `json:"egress,omitempty"`
}

// IngressReport shows declared vs detected metadata for the inbound prompt.
type IngressReport struct {
	Declared   *RequestHeaders          `json:"declared,omitempty"`
	Detected   *inspector.PromptMetadata `json:"detected"`
	Mismatches []Mismatch               `json:"mismatches"`
	Action     policy.Action            `json:"action"`
	RuleName   string                   `json:"rule_name,omitempty"`
}

// EgressReport shows detected metadata for the model output.
type EgressReport struct {
	Detected *inspector.PromptMetadata `json:"detected"`
	Action   policy.Action            `json:"action"`
	RuleName string                   `json:"rule_name,omitempty"`
}

// Mismatch records a discrepancy between what the agent declared and
// what DPI actually detected.
type Mismatch struct {
	Field    string `json:"field"`
	Declared any    `json:"declared"`
	Detected any    `json:"detected"`
	Severity string `json:"severity"` // "critical", "warning", "info"
}
