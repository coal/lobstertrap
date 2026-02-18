package policy

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/coal/lobstertrap/internal/inspector"
)

// NewMatchActionTable creates a table from rules, sorted by priority (highest first).
func NewMatchActionTable(rules []GuardRule, defaultAction Action) *MatchActionTable {
	sorted := make([]GuardRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})
	return &MatchActionTable{
		Rules:         sorted,
		DefaultAction: defaultAction,
	}
}

// Evaluate runs the metadata against the table. First matching rule wins.
func (t *MatchActionTable) Evaluate(meta *inspector.PromptMetadata) RuleResult {
	for _, rule := range t.Rules {
		if matchRule(rule, meta) {
			return RuleResult{
				Matched:     true,
				RuleName:    rule.Name,
				Action:      rule.Action,
				DenyMessage: rule.DenyMessage,
			}
		}
	}
	return RuleResult{
		Matched: false,
		Action:  t.DefaultAction,
	}
}

// matchRule returns true if ALL conditions in the rule match (AND logic).
func matchRule(rule GuardRule, meta *inspector.PromptMetadata) bool {
	for _, cond := range rule.Conditions {
		if !matchCondition(cond, meta) {
			return false
		}
	}
	return len(rule.Conditions) > 0
}

// matchCondition evaluates a single condition against the metadata.
func matchCondition(cond MatchCondition, meta *inspector.PromptMetadata) bool {
	result := evaluateCondition(cond, meta)
	if cond.Negate {
		return !result
	}
	return result
}

func evaluateCondition(cond MatchCondition, meta *inspector.PromptMetadata) bool {
	fieldVal := getFieldValue(cond.Field, meta)

	switch cond.MatchType {
	case MatchBoolean:
		return matchBoolean(fieldVal, cond.Value)
	case MatchExact:
		return matchExact(fieldVal, cond.Value)
	case MatchPrefix:
		return matchPrefix(fieldVal, cond.Value)
	case MatchContains:
		return matchContains(fieldVal, cond.Value)
	case MatchGlob:
		return matchGlob(fieldVal, cond.Value, cond.Field)
	case MatchRegex:
		return matchRegex(fieldVal, cond.Value)
	case MatchThreshold:
		return matchThreshold(fieldVal, cond.Value)
	case MatchRange:
		return matchRange(fieldVal, cond.Value)
	default:
		return false
	}
}

// getFieldValue extracts a field value from metadata by name.
func getFieldValue(field string, meta *inspector.PromptMetadata) any {
	switch field {
	case "intent_category":
		return string(meta.IntentCategory)
	case "intent_confidence":
		return meta.IntentConfidence
	case "risk_score":
		return meta.RiskScore
	case "contains_code":
		return meta.ContainsCode
	case "contains_credentials":
		return meta.ContainsCredentials
	case "contains_pii":
		return meta.ContainsPII
	case "contains_pii_request":
		return meta.ContainsPIIRequest
	case "contains_malware_request":
		return meta.ContainsMalwareRequest
	case "contains_phishing_patterns":
		return meta.ContainsPhishingPatterns
	case "contains_role_impersonation":
		return meta.ContainsRoleImpersonation
	case "contains_exfiltration":
		return meta.ContainsExfiltration
	case "contains_harm_patterns":
		return meta.ContainsHarmPatterns
	case "contains_obfuscation":
		return meta.ContainsObfuscation
	case "contains_system_commands":
		return meta.ContainsSystemCommands
	case "contains_injection_patterns":
		return meta.ContainsInjectionPatterns
	case "contains_file_paths":
		return meta.ContainsFilePaths
	case "contains_sensitive_paths":
		return meta.ContainsSensitivePaths
	case "contains_urls":
		return meta.ContainsURLs
	case "target_paths":
		return meta.TargetPaths
	case "target_domains":
		return meta.TargetDomains
	case "target_commands":
		return meta.TargetCommands
	case "token_count":
		return meta.TokenCount
	default:
		return nil
	}
}

func matchBoolean(fieldVal any, condVal any) bool {
	fb := toBool(fieldVal)
	cb := toBool(condVal)
	return fb == cb
}

func matchExact(fieldVal any, condVal any) bool {
	return fmt.Sprintf("%v", fieldVal) == fmt.Sprintf("%v", condVal)
}

func matchPrefix(fieldVal any, condVal any) bool {
	fs := fmt.Sprintf("%v", fieldVal)
	cs := fmt.Sprintf("%v", condVal)
	return strings.HasPrefix(fs, cs)
}

func matchContains(fieldVal any, condVal any) bool {
	cs := fmt.Sprintf("%v", condVal)

	// If field is a string slice, check if any element contains the value
	if slice, ok := fieldVal.([]string); ok {
		for _, s := range slice {
			if strings.Contains(s, cs) {
				return true
			}
		}
		return false
	}

	fs := fmt.Sprintf("%v", fieldVal)
	return strings.Contains(fs, cs)
}

func matchGlob(fieldVal any, condVal any, field string) bool {
	pattern := fmt.Sprintf("%v", condVal)

	// If field is a string slice (e.g., target_paths), check if any element matches
	if slice, ok := fieldVal.([]string); ok {
		for _, s := range slice {
			matched, err := filepath.Match(pattern, s)
			if err == nil && matched {
				return true
			}
		}
		return false
	}

	fs := fmt.Sprintf("%v", fieldVal)
	matched, err := filepath.Match(pattern, fs)
	return err == nil && matched
}

func matchRegex(fieldVal any, condVal any) bool {
	pattern := fmt.Sprintf("%v", condVal)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}

	// If field is a string slice, check any element
	if slice, ok := fieldVal.([]string); ok {
		for _, s := range slice {
			if re.MatchString(s) {
				return true
			}
		}
		return false
	}

	fs := fmt.Sprintf("%v", fieldVal)
	return re.MatchString(fs)
}

func matchThreshold(fieldVal any, condVal any) bool {
	fv := toFloat64(fieldVal)
	cv := toFloat64(condVal)
	return fv >= cv
}

func matchRange(fieldVal any, condVal any) bool {
	fv := toFloat64(fieldVal)
	// Range expects "min-max" string
	cs := fmt.Sprintf("%v", condVal)
	parts := strings.SplitN(cs, "-", 2)
	if len(parts) != 2 {
		return false
	}
	min, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	max, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err1 != nil || err2 != nil {
		return false
	}
	return fv >= min && fv <= max
}

func toBool(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	case int:
		return b != 0
	case float64:
		return b != 0
	default:
		return false
	}
}

func toFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	default:
		return 0
	}
}
