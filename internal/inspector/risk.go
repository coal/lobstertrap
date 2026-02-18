package inspector

// SignalWeights defines how much each boolean signal contributes to risk score.
var SignalWeights = map[string]float64{
	"contains_credentials":        0.35,
	"contains_pii":                0.25,
	"contains_pii_request":        0.30,
	"contains_malware_request":    0.45,
	"contains_phishing_patterns":  0.40,
	"contains_role_impersonation": 0.25,
	"contains_exfiltration":       0.40,
	"contains_harm_patterns":      0.50,
	"contains_obfuscation":        0.35,
	"contains_injection_patterns": 0.40,
	"contains_system_commands":    0.30,
	"contains_file_paths":         0.05,
	"contains_urls":               0.05,
	"contains_code":               0.02,
	"sensitive_paths":             0.25,
}

// IntentWeights adds risk based on intent category.
var IntentWeights = map[IntentCategory]float64{
	IntentCredentialAccess: 0.30,
	IntentSystem:           0.25,
	IntentNetwork:          0.10,
	IntentCodeExecution:    0.10,
	IntentFileIO:           0.05,
	IntentDataAccess:       0.10,
	IntentCommunication:    0.05,
	IntentGeneral:          0.00,
}

// RiskSignals holds the boolean signals used for risk computation.
type RiskSignals struct {
	ContainsCredentials       bool
	ContainsPII               bool
	ContainsPIIRequest        bool
	ContainsMalwareRequest    bool
	ContainsPhishingPatterns  bool
	ContainsRoleImpersonation bool
	ContainsExfiltration      bool
	ContainsHarmPatterns      bool
	ContainsObfuscation       bool
	ContainsInjectionPatterns bool
	ContainsSystemCommands    bool
	ContainsFilePaths         bool
	ContainsURLs              bool
	ContainsCode              bool
	HasSensitivePaths         bool
	Intent                    IntentCategory
	IntentConfidence          float64
}

// ComputeRisk calculates a composite risk score from 0.0 to 1.0.
func ComputeRisk(signals RiskSignals) float64 {
	score := 0.0

	if signals.ContainsCredentials {
		score += SignalWeights["contains_credentials"]
	}
	if signals.ContainsPII {
		score += SignalWeights["contains_pii"]
	}
	if signals.ContainsPIIRequest {
		score += SignalWeights["contains_pii_request"]
	}
	if signals.ContainsMalwareRequest {
		score += SignalWeights["contains_malware_request"]
	}
	if signals.ContainsPhishingPatterns {
		score += SignalWeights["contains_phishing_patterns"]
	}
	if signals.ContainsRoleImpersonation {
		score += SignalWeights["contains_role_impersonation"]
	}
	if signals.ContainsExfiltration {
		score += SignalWeights["contains_exfiltration"]
	}
	if signals.ContainsHarmPatterns {
		score += SignalWeights["contains_harm_patterns"]
	}
	if signals.ContainsObfuscation {
		score += SignalWeights["contains_obfuscation"]
	}
	if signals.ContainsInjectionPatterns {
		score += SignalWeights["contains_injection_patterns"]
	}
	if signals.ContainsSystemCommands {
		score += SignalWeights["contains_system_commands"]
	}
	if signals.ContainsFilePaths {
		score += SignalWeights["contains_file_paths"]
	}
	if signals.ContainsURLs {
		score += SignalWeights["contains_urls"]
	}
	if signals.ContainsCode {
		score += SignalWeights["contains_code"]
	}
	if signals.HasSensitivePaths {
		score += SignalWeights["sensitive_paths"]
	}

	// Add intent-based risk, scaled by confidence
	if w, ok := IntentWeights[signals.Intent]; ok {
		score += w * signals.IntentConfidence
	}

	// Clamp to [0, 1]
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	return score
}
