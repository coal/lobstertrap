package inspector

import (
	"regexp"
	"strings"
)

// IntentCategory represents a classified prompt intent.
type IntentCategory string

const (
	IntentCodeExecution   IntentCategory = "code_execution"
	IntentFileIO          IntentCategory = "file_io"
	IntentNetwork         IntentCategory = "network"
	IntentSystem          IntentCategory = "system"
	IntentCommunication   IntentCategory = "communication"
	IntentCredentialAccess IntentCategory = "credential_access"
	IntentDataAccess      IntentCategory = "data_access"
	IntentGeneral         IntentCategory = "general"
)

// ClassificationResult holds intent classification output.
type ClassificationResult struct {
	Category   IntentCategory
	Confidence float64
}

// intentRule maps keyword patterns to an intent category with a weight.
type intentRule struct {
	pattern  *regexp.Regexp
	category IntentCategory
	weight   float64
}

var intentRules = []intentRule{
	// Code execution signals
	{regexp.MustCompile(`(?i)\b(execute|run|compile|eval|exec|invoke|spawn|subprocess|shell)\b`), IntentCodeExecution, 0.8},
	{regexp.MustCompile(`(?i)\b(python|node|bash|ruby|perl|java|go\s+run|gcc|make|npm|pip)\b`), IntentCodeExecution, 0.7},
	{regexp.MustCompile("(?i)```(python|bash|sh|javascript|go|ruby)"), IntentCodeExecution, 0.6},

	// File I/O signals
	{regexp.MustCompile(`(?i)\b(read|write|open|create|delete|remove|copy|move|rename|mkdir|touch|cat|ls|dir)\b.*\b(file|directory|folder|path)\b`), IntentFileIO, 0.8},
	{regexp.MustCompile(`(?i)\b(read|write|open|save|load|dump|append)\s+(to|from|the)\s+(file|disk|directory)`), IntentFileIO, 0.9},
	{regexp.MustCompile(`(?i)\b(cat|head|tail|less|more|nano|vim|vi|emacs)\s+\S`), IntentFileIO, 0.7},

	// Network signals
	{regexp.MustCompile(`(?i)\b(curl|wget|fetch|http|https|request|download|upload|api\s+call|post\s+to|get\s+from)\b`), IntentNetwork, 0.8},
	{regexp.MustCompile(`(?i)\b(connect|socket|tcp|udp|dns|ping|traceroute|ssh|ftp|telnet)\b`), IntentNetwork, 0.7},
	{regexp.MustCompile(`(?i)\b(send|transmit|upload|exfiltrate|forward)\b.*\b(data|file|info|result)\b`), IntentNetwork, 0.7},

	// System signals
	{regexp.MustCompile(`(?i)\b(sudo|su\s|chmod|chown|mount|umount|systemctl|service|cron|kill|pkill|reboot|shutdown)\b`), IntentSystem, 0.9},
	{regexp.MustCompile(`(?i)\b(process|daemon|kernel|boot|init|grub|partition|disk)\b`), IntentSystem, 0.5},

	// Communication signals
	{regexp.MustCompile(`(?i)\b(email|send\s+mail|smtp|message|notify|alert|slack|webhook|sms|text)\b`), IntentCommunication, 0.8},

	// Credential access signals
	{regexp.MustCompile(`(?i)\b(password|credential|secret|key|token|auth|login|decrypt|crack|hash|brute)\b`), IntentCredentialAccess, 0.7},
	{regexp.MustCompile(`(?i)\b(\.env|passwd|shadow|keychain|vault|keyring)\b`), IntentCredentialAccess, 0.8},

	// Data access signals
	{regexp.MustCompile(`(?i)\b(database|sql|query|select|insert|update|delete\s+from|drop\s+table|mongodb|redis|postgres)\b`), IntentDataAccess, 0.8},
	{regexp.MustCompile(`(?i)\b(scrape|crawl|extract|parse|collect)\b.*\b(data|info|page|site)\b`), IntentDataAccess, 0.6},
}

// Classify determines the most likely intent category for the given text.
func Classify(text string) ClassificationResult {
	lower := strings.ToLower(text)
	scores := make(map[IntentCategory]float64)
	counts := make(map[IntentCategory]int)

	for _, rule := range intentRules {
		if rule.pattern.MatchString(lower) {
			scores[rule.category] += rule.weight
			counts[rule.category]++
		}
	}

	if len(scores) == 0 {
		return ClassificationResult{
			Category:   IntentGeneral,
			Confidence: 0.5,
		}
	}

	// Find highest scoring category
	var bestCategory IntentCategory
	var bestScore float64
	for cat, score := range scores {
		if score > bestScore {
			bestScore = score
			bestCategory = cat
		}
	}

	// Normalize confidence: base on score relative to max possible
	confidence := bestScore / (bestScore + 1.0) // sigmoid-like normalization
	if confidence > 1.0 {
		confidence = 1.0
	}

	return ClassificationResult{
		Category:   bestCategory,
		Confidence: confidence,
	}
}
