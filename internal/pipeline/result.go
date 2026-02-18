package pipeline

import (
	"github.com/coal/lobstertrap/internal/inspector"
	"github.com/coal/lobstertrap/internal/metadata"
	"github.com/coal/lobstertrap/internal/policy"
)

// PipelineResult captures the full decision chain for a single request.
type PipelineResult struct {
	RequestID       string                   `json:"request_id"`
	IngressMetadata *inspector.PromptMetadata `json:"ingress_metadata,omitempty"`
	IngressResult   *policy.RuleResult       `json:"ingress_result"`
	EgressMetadata  *inspector.PromptMetadata `json:"egress_metadata,omitempty"`
	EgressResult    *policy.RuleResult       `json:"egress_result,omitempty"`
	Blocked         bool                     `json:"blocked"`
	BlockedAt       string                   `json:"blocked_at,omitempty"` // "ingress" or "egress"
	DenyMessage     string                   `json:"deny_message,omitempty"`
	DeclaredHeaders *metadata.RequestHeaders `json:"declared_headers,omitempty"`
	Mismatches      []metadata.Mismatch      `json:"mismatches,omitempty"`
}

// IsBlocked returns true if the request was blocked at any stage.
func (r *PipelineResult) IsBlocked() bool {
	return r.Blocked
}

// ShouldForward returns true if the request should be forwarded to the backend.
func (r *PipelineResult) ShouldForward() bool {
	if r.IngressResult == nil {
		return true
	}
	return r.IngressResult.Action != policy.ActionDeny &&
		r.IngressResult.Action != policy.ActionQuarantine
}

// NeedsHumanReview returns true if any stage flagged HUMAN_REVIEW.
func (r *PipelineResult) NeedsHumanReview() bool {
	if r.IngressResult != nil && r.IngressResult.Action == policy.ActionHumanReview {
		return true
	}
	if r.EgressResult != nil && r.EgressResult.Action == policy.ActionHumanReview {
		return true
	}
	return false
}

// BuildResponseHeaders assembles the full Lobster Trap response headers
// from this pipeline result.
func (r *PipelineResult) BuildResponseHeaders() *metadata.ResponseHeaders {
	rh := &metadata.ResponseHeaders{
		RequestID: r.RequestID,
		Verdict:   r.overallVerdict(),
	}

	// Ingress report
	if r.IngressResult != nil {
		rh.Ingress = &metadata.IngressReport{
			Declared:   r.DeclaredHeaders,
			Detected:   r.IngressMetadata,
			Mismatches: r.Mismatches,
			Action:     r.IngressResult.Action,
			RuleName:   r.IngressResult.RuleName,
		}
		if rh.Ingress.Mismatches == nil {
			rh.Ingress.Mismatches = []metadata.Mismatch{}
		}
	}

	// Egress report
	if r.EgressResult != nil {
		rh.Egress = &metadata.EgressReport{
			Detected: r.EgressMetadata,
			Action:   r.EgressResult.Action,
			RuleName: r.EgressResult.RuleName,
		}
	}

	return rh
}

// overallVerdict returns the top-level verdict string.
func (r *PipelineResult) overallVerdict() string {
	if r.Blocked {
		return "DENY"
	}
	if r.NeedsHumanReview() {
		return "HUMAN_REVIEW"
	}
	return "ALLOW"
}
