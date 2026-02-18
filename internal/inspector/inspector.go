package inspector

import "strings"

// PromptMetadata holds all extracted metadata from a prompt or response text.
type PromptMetadata struct {
	IntentCategory            string   `json:"intent_category"`
	IntentConfidence          float64  `json:"intent_confidence"`
	RiskScore                 float64  `json:"risk_score"`
	ContainsCode              bool     `json:"contains_code"`
	ContainsCredentials       bool     `json:"contains_credentials"`
	ContainsPII               bool     `json:"contains_pii"`
	ContainsPIIRequest        bool     `json:"contains_pii_request"`
	ContainsSystemCommands    bool     `json:"contains_system_commands"`
	ContainsMalwareRequest    bool     `json:"contains_malware_request"`
	ContainsPhishingPatterns  bool     `json:"contains_phishing_patterns"`
	ContainsRoleImpersonation bool     `json:"contains_role_impersonation"`
	ContainsExfiltration      bool     `json:"contains_exfiltration"`
	ContainsHarmPatterns      bool     `json:"contains_harm_patterns"`
	ContainsObfuscation       bool     `json:"contains_obfuscation"`
	ContainsInjectionPatterns bool     `json:"contains_injection_patterns"`
	ContainsFilePaths         bool     `json:"contains_file_paths"`
	ContainsSensitivePaths    bool     `json:"contains_sensitive_paths"`
	ContainsURLs              bool     `json:"contains_urls"`
	TargetPaths               []string `json:"target_paths"`
	TargetDomains             []string `json:"target_domains"`
	TargetCommands            []string `json:"target_commands"`
	TokenCount                int      `json:"token_count"`
}

// Inspector is the DPI engine. It extracts structured metadata from text
// using compiled regex patterns — no LLM call involved.
type Inspector struct{}

// New creates a new Inspector.
func New() *Inspector {
	return &Inspector{}
}

// Inspect extracts metadata from the given text.
func (ins *Inspector) Inspect(text string) *PromptMetadata {
	meta := &PromptMetadata{}

	// Boolean signals
	meta.ContainsCredentials = CredentialPatterns.MatchAny(text)
	meta.ContainsPII = PIIPatterns.MatchAny(text)
	meta.ContainsPIIRequest = PIIRequestPatterns.MatchAny(text)
	meta.ContainsMalwareRequest = MalwareRequestPatterns.MatchAny(text)
	meta.ContainsPhishingPatterns = PhishingPatterns.MatchAny(text)
	meta.ContainsRoleImpersonation = RoleImpersonationPatterns.MatchAny(text)
	meta.ContainsExfiltration = ExfiltrationPatterns.MatchAny(text)
	meta.ContainsHarmPatterns = HarmPatterns.MatchAny(text)
	meta.ContainsObfuscation = ObfuscationPatterns.MatchAny(text)
	meta.ContainsInjectionPatterns = InjectionPatterns.MatchAny(text)
	meta.ContainsSystemCommands = ShellCommandPatterns.MatchAny(text)
	meta.ContainsCode = CodePatterns.MatchAny(text)
	meta.ContainsURLs = URLPatterns.MatchAny(text)

	// Extract file paths
	meta.TargetPaths = FilePathPatterns.FindAll(text)
	meta.ContainsFilePaths = len(meta.TargetPaths) > 0

	// Check for sensitive paths
	hasSensitivePaths := SensitivePathPatterns.MatchAny(text)
	meta.ContainsSensitivePaths = hasSensitivePaths

	// Extract domains from URLs
	if matches := DomainExtractPattern.FindAllStringSubmatch(text, -1); len(matches) > 0 {
		seen := make(map[string]struct{})
		for _, m := range matches {
			if len(m) > 1 {
				domain := strings.ToLower(m[1])
				if _, ok := seen[domain]; !ok {
					seen[domain] = struct{}{}
					meta.TargetDomains = append(meta.TargetDomains, domain)
				}
			}
		}
	}

	// Extract commands
	meta.TargetCommands = CommandExtractPatterns.FindAll(text)

	// Classify intent
	classification := Classify(text)
	meta.IntentCategory = string(classification.Category)
	meta.IntentConfidence = classification.Confidence

	// Compute risk score
	meta.RiskScore = ComputeRisk(RiskSignals{
		ContainsCredentials:       meta.ContainsCredentials,
		ContainsPII:               meta.ContainsPII,
		ContainsPIIRequest:        meta.ContainsPIIRequest,
		ContainsMalwareRequest:    meta.ContainsMalwareRequest,
		ContainsPhishingPatterns:  meta.ContainsPhishingPatterns,
		ContainsRoleImpersonation: meta.ContainsRoleImpersonation,
		ContainsExfiltration:      meta.ContainsExfiltration,
		ContainsHarmPatterns:      meta.ContainsHarmPatterns,
		ContainsObfuscation:       meta.ContainsObfuscation,
		ContainsInjectionPatterns: meta.ContainsInjectionPatterns,
		ContainsSystemCommands:    meta.ContainsSystemCommands,
		ContainsFilePaths:         meta.ContainsFilePaths,
		ContainsURLs:              meta.ContainsURLs,
		ContainsCode:              meta.ContainsCode,
		HasSensitivePaths:         hasSensitivePaths,
		Intent:                    classification.Category,
		IntentConfidence:          classification.Confidence,
	})

	// Rough token estimate (~4 chars per token)
	meta.TokenCount = estimateTokens(text)

	return meta
}

// estimateTokens gives a rough token count (~4 chars per token for English).
func estimateTokens(text string) int {
	if len(text) == 0 {
		return 0
	}
	// Rough heuristic: ~4 characters per token
	tokens := len(text) / 4
	if tokens == 0 {
		tokens = 1
	}
	return tokens
}
