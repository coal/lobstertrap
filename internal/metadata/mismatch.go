package metadata

import (
	"github.com/coal/lobstertrap/internal/inspector"
)

// highRiskIntents are intent categories where a mismatch is critical.
var highRiskIntents = map[string]bool{
	"credential_access": true,
	"system":            true,
	"network":           true,
}

// DetectMismatches compares agent-declared headers against DPI-detected
// metadata and returns any discrepancies. An empty slice means the agent
// was honest (or didn't declare anything).
func DetectMismatches(declared *RequestHeaders, detected *inspector.PromptMetadata) []Mismatch {
	if declared == nil {
		return nil
	}

	var mismatches []Mismatch

	// Intent mismatch
	if declared.DeclaredIntent != "" && declared.DeclaredIntent != detected.IntentCategory {
		severity := "warning"
		if highRiskIntents[detected.IntentCategory] {
			severity = "critical"
		}
		mismatches = append(mismatches, Mismatch{
			Field:    "intent",
			Declared: declared.DeclaredIntent,
			Detected: detected.IntentCategory,
			Severity: severity,
		})
	}

	// Undeclared paths: anything DPI found that the agent didn't declare
	if len(detected.TargetPaths) > 0 {
		undeclared := findUndeclared(declared.DeclaredPaths, detected.TargetPaths)
		if len(undeclared) > 0 {
			mismatches = append(mismatches, Mismatch{
				Field:    "paths",
				Declared: declared.DeclaredPaths,
				Detected: undeclared,
				Severity: "warning",
			})
		}
	}

	// Undeclared commands
	if len(detected.TargetCommands) > 0 {
		undeclared := findUndeclared(declared.DeclaredCommands, detected.TargetCommands)
		if len(undeclared) > 0 {
			mismatches = append(mismatches, Mismatch{
				Field:    "commands",
				Declared: declared.DeclaredCommands,
				Detected: undeclared,
				Severity: "critical",
			})
		}
	}

	// Undeclared domains
	if len(detected.TargetDomains) > 0 {
		undeclared := findUndeclared(declared.DeclaredDomains, detected.TargetDomains)
		if len(undeclared) > 0 {
			mismatches = append(mismatches, Mismatch{
				Field:    "domains",
				Declared: declared.DeclaredDomains,
				Detected: undeclared,
				Severity: "warning",
			})
		}
	}

	return mismatches
}

// findUndeclared returns items in detected that are not in declared.
func findUndeclared(declared, detected []string) []string {
	if len(declared) == 0 {
		// Agent declared nothing but DPI found items — all are undeclared.
		return detected
	}
	set := make(map[string]struct{}, len(declared))
	for _, d := range declared {
		set[d] = struct{}{}
	}
	var undeclared []string
	for _, d := range detected {
		if _, ok := set[d]; !ok {
			undeclared = append(undeclared, d)
		}
	}
	return undeclared
}
