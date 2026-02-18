package policy

import (
	"testing"

	"github.com/coal/lobstertrap/internal/inspector"
)

func TestMatchBoolean(t *testing.T) {
	table := NewMatchActionTable([]GuardRule{
		{
			Name:        "block_injection",
			Priority:    100,
			Action:      ActionDeny,
			DenyMessage: "Injection blocked",
			Conditions: []MatchCondition{
				{Field: "contains_injection_patterns", MatchType: MatchBoolean, Value: true},
			},
		},
	}, ActionAllow)

	// Should match
	meta := &inspector.PromptMetadata{ContainsInjectionPatterns: true}
	result := table.Evaluate(meta)
	if result.Action != ActionDeny {
		t.Errorf("expected DENY, got %s", result.Action)
	}
	if result.RuleName != "block_injection" {
		t.Errorf("expected rule block_injection, got %s", result.RuleName)
	}

	// Should not match
	meta2 := &inspector.PromptMetadata{ContainsInjectionPatterns: false}
	result2 := table.Evaluate(meta2)
	if result2.Action != ActionAllow {
		t.Errorf("expected ALLOW (default), got %s", result2.Action)
	}
}

func TestMatchThreshold(t *testing.T) {
	table := NewMatchActionTable([]GuardRule{
		{
			Name:     "high_risk",
			Priority: 70,
			Action:   ActionHumanReview,
			Conditions: []MatchCondition{
				{Field: "risk_score", MatchType: MatchThreshold, Value: 0.6},
			},
		},
	}, ActionAllow)

	// Above threshold
	meta := &inspector.PromptMetadata{RiskScore: 0.8}
	result := table.Evaluate(meta)
	if result.Action != ActionHumanReview {
		t.Errorf("expected HUMAN_REVIEW, got %s", result.Action)
	}

	// Below threshold
	meta2 := &inspector.PromptMetadata{RiskScore: 0.3}
	result2 := table.Evaluate(meta2)
	if result2.Action != ActionAllow {
		t.Errorf("expected ALLOW, got %s", result2.Action)
	}
}

func TestMatchExact(t *testing.T) {
	table := NewMatchActionTable([]GuardRule{
		{
			Name:     "log_code",
			Priority: 30,
			Action:   ActionLog,
			Conditions: []MatchCondition{
				{Field: "intent_category", MatchType: MatchExact, Value: "code_execution"},
			},
		},
	}, ActionAllow)

	meta := &inspector.PromptMetadata{IntentCategory: "code_execution"}
	result := table.Evaluate(meta)
	if result.Action != ActionLog {
		t.Errorf("expected LOG, got %s", result.Action)
	}

	meta2 := &inspector.PromptMetadata{IntentCategory: "general"}
	result2 := table.Evaluate(meta2)
	if result2.Action != ActionAllow {
		t.Errorf("expected ALLOW, got %s", result2.Action)
	}
}

func TestMatchGlob(t *testing.T) {
	table := NewMatchActionTable([]GuardRule{
		{
			Name:        "block_etc",
			Priority:    85,
			Action:      ActionDeny,
			DenyMessage: "Sensitive path",
			Conditions: []MatchCondition{
				{Field: "target_paths", MatchType: MatchGlob, Value: "/etc/*"},
			},
		},
	}, ActionAllow)

	meta := &inspector.PromptMetadata{TargetPaths: []string{"/etc/shadow"}}
	result := table.Evaluate(meta)
	if result.Action != ActionDeny {
		t.Errorf("expected DENY, got %s", result.Action)
	}

	meta2 := &inspector.PromptMetadata{TargetPaths: []string{"/tmp/safe.txt"}}
	result2 := table.Evaluate(meta2)
	if result2.Action != ActionAllow {
		t.Errorf("expected ALLOW, got %s", result2.Action)
	}
}

func TestMatchNegate(t *testing.T) {
	table := NewMatchActionTable([]GuardRule{
		{
			Name:     "allow_only_general",
			Priority: 50,
			Action:   ActionDeny,
			Conditions: []MatchCondition{
				{Field: "intent_category", MatchType: MatchExact, Value: "general", Negate: true},
			},
		},
	}, ActionAllow)

	// Not general → should match (negate makes "not exact match" true)
	meta := &inspector.PromptMetadata{IntentCategory: "code_execution"}
	result := table.Evaluate(meta)
	if result.Action != ActionDeny {
		t.Errorf("expected DENY for non-general intent, got %s", result.Action)
	}

	// General → negate makes it false, so no match → default ALLOW
	meta2 := &inspector.PromptMetadata{IntentCategory: "general"}
	result2 := table.Evaluate(meta2)
	if result2.Action != ActionAllow {
		t.Errorf("expected ALLOW for general intent, got %s", result2.Action)
	}
}

func TestPriorityOrdering(t *testing.T) {
	table := NewMatchActionTable([]GuardRule{
		{
			Name:     "low_priority",
			Priority: 10,
			Action:   ActionLog,
			Conditions: []MatchCondition{
				{Field: "contains_code", MatchType: MatchBoolean, Value: true},
			},
		},
		{
			Name:     "high_priority",
			Priority: 100,
			Action:   ActionDeny,
			Conditions: []MatchCondition{
				{Field: "contains_code", MatchType: MatchBoolean, Value: true},
			},
		},
	}, ActionAllow)

	meta := &inspector.PromptMetadata{ContainsCode: true}
	result := table.Evaluate(meta)
	if result.Action != ActionDeny {
		t.Errorf("expected high priority DENY, got %s", result.Action)
	}
	if result.RuleName != "high_priority" {
		t.Errorf("expected high_priority rule, got %s", result.RuleName)
	}
}

func TestANDLogic(t *testing.T) {
	table := NewMatchActionTable([]GuardRule{
		{
			Name:     "multi_condition",
			Priority: 80,
			Action:   ActionDeny,
			Conditions: []MatchCondition{
				{Field: "contains_system_commands", MatchType: MatchBoolean, Value: true},
				{Field: "risk_score", MatchType: MatchThreshold, Value: 0.3},
			},
		},
	}, ActionAllow)

	// Both conditions true
	meta := &inspector.PromptMetadata{ContainsSystemCommands: true, RiskScore: 0.5}
	result := table.Evaluate(meta)
	if result.Action != ActionDeny {
		t.Errorf("expected DENY when both conditions match, got %s", result.Action)
	}

	// Only one condition true
	meta2 := &inspector.PromptMetadata{ContainsSystemCommands: true, RiskScore: 0.1}
	result2 := table.Evaluate(meta2)
	if result2.Action != ActionAllow {
		t.Errorf("expected ALLOW when only one condition matches, got %s", result2.Action)
	}
}

func TestLoadDefaultPolicy(t *testing.T) {
	pol, err := LoadFromFile("../../configs/default_policy.yaml")
	if err != nil {
		t.Fatalf("failed to load default policy: %v", err)
	}
	if pol.PolicyName != "default" {
		t.Errorf("expected policy name 'default', got %q", pol.PolicyName)
	}
	if len(pol.IngressRules) == 0 {
		t.Error("expected ingress rules")
	}
	if len(pol.EgressRules) == 0 {
		t.Error("expected egress rules")
	}
}
