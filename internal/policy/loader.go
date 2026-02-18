package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFromFile loads a policy from a YAML file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return Parse(data)
}

// Parse parses YAML bytes into a Policy.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	if err := validate(&p); err != nil {
		return nil, fmt.Errorf("validating policy: %w", err)
	}
	return &p, nil
}

// validate checks policy integrity.
func validate(p *Policy) error {
	if p.Version == "" {
		return fmt.Errorf("policy version is required")
	}
	if p.PolicyName == "" {
		return fmt.Errorf("policy_name is required")
	}
	if p.DefaultAction == "" {
		p.DefaultAction = ActionAllow
	}

	validActions := map[Action]bool{
		ActionAllow: true, ActionDeny: true, ActionLog: true,
		ActionModify: true, ActionQuarantine: true, ActionHumanReview: true,
		ActionRateLimit: true, ActionRedirect: true,
	}

	for i, rule := range p.IngressRules {
		if rule.Name == "" {
			return fmt.Errorf("ingress rule %d: name is required", i)
		}
		if !validActions[rule.Action] {
			return fmt.Errorf("ingress rule %q: invalid action %q", rule.Name, rule.Action)
		}
		if len(rule.Conditions) == 0 {
			return fmt.Errorf("ingress rule %q: at least one condition is required", rule.Name)
		}
	}

	for i, rule := range p.EgressRules {
		if rule.Name == "" {
			return fmt.Errorf("egress rule %d: name is required", i)
		}
		if !validActions[rule.Action] {
			return fmt.Errorf("egress rule %q: invalid action %q", rule.Name, rule.Action)
		}
		if len(rule.Conditions) == 0 {
			return fmt.Errorf("egress rule %q: at least one condition is required", rule.Name)
		}
	}

	return nil
}

// BuildTables creates ingress and egress MatchActionTables from the policy.
func BuildTables(p *Policy) (ingress *MatchActionTable, egress *MatchActionTable) {
	ingress = NewMatchActionTable(p.IngressRules, p.DefaultAction)
	egress = NewMatchActionTable(p.EgressRules, p.DefaultAction)
	return
}
