package inspector

import "regexp"

// PatternSet holds compiled regex patterns for a specific category.
type PatternSet struct {
	Name     string
	Patterns []*regexp.Regexp
}

// compile is a helper that compiles a list of regex strings into a PatternSet.
// Panics on invalid patterns (they are compile-time constants).
func compile(name string, patterns []string) PatternSet {
	ps := PatternSet{Name: name, Patterns: make([]*regexp.Regexp, len(patterns))}
	for i, p := range patterns {
		ps.Patterns[i] = regexp.MustCompile(p)
	}
	return ps
}

// MatchAny returns true if any pattern in the set matches the text.
func (ps *PatternSet) MatchAny(text string) bool {
	for _, p := range ps.Patterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

// FindAll returns all unique matches across all patterns.
func (ps *PatternSet) FindAll(text string) []string {
	seen := make(map[string]struct{})
	var results []string
	for _, p := range ps.Patterns {
		matches := p.FindAllString(text, -1)
		for _, m := range matches {
			if _, ok := seen[m]; !ok {
				seen[m] = struct{}{}
				results = append(results, m)
			}
		}
	}
	return results
}

// --- Credential Patterns ---

var CredentialPatterns = compile("credentials", []string{
	// Generic API keys (sk-, pk- prefixed)
	`(?i)\b(sk|pk)-[a-zA-Z0-9]{20,}\b`,
	// api_key=... or api-key=...
	`(?i)(api[_-]?key|apikey)\s*[=:]\s*["']?[a-zA-Z0-9_\-]{20,}`,
	// Bearer tokens
	`(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`,
	// token=...
	`(?i)\btoken\s*[=:]\s*["']?[a-zA-Z0-9_\-]{20,}`,
	// Password assignments
	`(?i)(password|passwd|pwd)\s*[=:]\s*["']?\S{4,}`,
	// AWS keys
	`(?i)(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|aws_secret|aws_key)\s*[=:]\s*["']?\S+`,
	// Azure keys
	`(?i)(AZURE_KEY|AZURE_SECRET|AZURE_STORAGE_KEY)\s*[=:]\s*["']?\S+`,
	// OpenAI API key
	`(?i)OPENAI_API_KEY\s*[=:]\s*["']?\S+`,
	// Private keys
	`-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY-----`,
	// GitHub PATs
	`\bghp_[a-zA-Z0-9]{36}\b`,
	// GitHub fine-grained tokens
	`\bgithub_pat_[a-zA-Z0-9_]{22,}\b`,
	// JWTs
	`\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`,
	// Generic secret assignments
	`(?i)(secret|SECRET_KEY|CLIENT_SECRET)\s*[=:]\s*["']?\S{8,}`,
})

// --- PII Patterns ---

var PIIPatterns = compile("pii", []string{
	// SSN
	`\b\d{3}-\d{2}-\d{4}\b`,
	// Credit card numbers (basic)
	`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
	// US phone numbers
	`\b\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b`,
	// Email addresses
	`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`,
})

// --- PII Request Patterns (asking FOR sensitive data, not containing it) ---

var PIIRequestPatterns = compile("pii_request", []string{
	// Asking for SSN
	`(?i)\b(social\s+security\s+(number|#|no\.?))\b`,
	`(?i)\b(ssn|SSN)\b`,
	// Asking for credit card info
	`(?i)\b(credit\s+card\s*(number|#|no\.?|info|detail))\b`,
	`(?i)\b(card\s*number|CVV|CVC|expir(y|ation)\s*date)\b`,
	// Asking for personal identification
	`(?i)\b(date\s+of\s+birth|DOB|birth\s*date)\b`,
	`(?i)\b(driver'?s?\s+licen[sc]e\s*(number|#|no\.?))\b`,
	`(?i)\b(passport\s*(number|#|no\.?|info|detail))\b`,
	`(?i)\b(national\s+id|national\s+identification)\b`,
	// Asking for financial/account info
	`(?i)\b(bank\s+account\s*(number|#|no\.?|info|detail|routing))\b`,
	`(?i)\baccount\s*(number|#|no\.?|info|detail|balance)s?\b`,
	`(?i)\b(routing\s+number)\b`,
	`(?i)\b(tax\s+id|taxpayer\s+identification|EIN|TIN)\b`,
	// Asking for addresses/phone/email of specific people
	`(?i)\b(home\s+address|mailing\s+address|phone\s+number|cell\s+number|mobile\s+number)\b.*\b(of|for|belonging\s+to)\b`,
	// Asking for passwords/credentials of specific people or accounts
	`(?i)\b(password|passwd|login\s+credentials?)\s+(for|of|to|belonging\s+to)\b`,
	// Asking for medical info
	`(?i)\b(medical\s+record|health\s+record|diagnosis|prescription|patient\s+info)\b`,
	// Generic "give me someone's PII" patterns
	`(?i)\b(tell|give|show|provide|share|reveal|disclose|leak)\b.{0,30}\b(social\s+security|ssn|credit\s+card|passport|driver'?s?\s+licen[sc]e|bank\s+account|medical\s+record|account\s*(number|detail|info))\b`,
	`(?i)\b(what\s+is|what'?s)\b.{0,30}\b(social\s+security|ssn|credit\s+card|passport|driver'?s?\s+licen[sc]e|bank\s+account|account\s*(number|detail|info))\b`,
	// Look up / find someone's private data
	`(?i)\b(look\s+up|find|search|retrieve|access|get)\b.{0,30}\b(personal\s+(info|information|data|detail)|private\s+(info|information|data|detail))\b`,
	// Possessive requests for account/private data ("Joe's account", "his details", "their records")
	`(?i)\b\w+'?s\s+account\s*(detail|info|number|balance)s?\b`,
	`(?i)\b(his|her|their|someone'?s?)\s+(account|financial|banking|personal)\s+(detail|info|data|record|number)s?\b`,
	// "I need [person]'s [sensitive thing]"
	`(?i)\b(need|want|require|give\s+me)\b.{0,30}\b(account\s*(detail|info|number|balance)|personal\s+(detail|info|data)|private\s+(detail|info|data))\b`,
})

// --- Malware / Exploit Request Patterns ---

var MalwareRequestPatterns = compile("malware_request", []string{
	// Direct malware requests
	`(?i)\b(write|create|build|generate|make|code|develop)\b.{0,30}\b(malware|virus|trojan|worm|ransomware|spyware|adware|rootkit|botnet|backdoor)\b`,
	`(?i)\b(write|create|build|generate|make|code|develop)\b.{0,30}\b(keylogger|key\s*logger|screen\s*scraper|credential\s*stealer|password\s*stealer)\b`,
	// Exploit development
	`(?i)\b(write|create|build|generate|develop)\b.{0,30}\b(exploit|payload|shellcode|reverse\s*shell|bind\s*shell|web\s*shell)\b`,
	`(?i)\b(buffer\s+overflow|stack\s+smash|heap\s+spray|use.after.free|format\s+string\s+attack|ROP\s+chain)\b`,
	`(?i)\b(CVE-\d{4}-\d+)\b.*\b(exploit|payload|PoC|proof\s+of\s+concept)\b`,
	// Offensive tools
	`(?i)\b(write|create|build)\b.{0,30}\b(RAT|remote\s+access\s+trojan|C2\s+server|command\s+and\s+control)\b`,
	`(?i)\b(write|create|build)\b.{0,30}\b(cryptominer|crypto\s*miner|coin\s*miner)\b`,
	// Code injection
	`(?i)\b(write|create|generate)\b.{0,30}\b(SQL\s+injection|XSS|cross.site\s+scripting|CSRF|code\s+injection)\b.*\b(payload|attack|exploit|script)\b`,
	// Bypass/evasion tools
	`(?i)\b(write|create|build)\b.{0,30}\b(antivirus\s+evas|AV\s+evas|EDR\s+evas|detection\s+evas|firewall\s+bypass)\b`,
	// Phishing kits
	`(?i)\b(write|create|build|generate)\b.{0,30}\b(phishing\s+kit|credential\s+harvester|login\s+page\s+clone)\b`,
	// DDoS
	`(?i)\b(write|create|build|launch)\b.{0,30}\b(DDoS|denial\s+of\s+service|flood\s+attack|stress\s*test\s+tool)\b`,
})

// --- Phishing / Fraud Patterns ---

var PhishingPatterns = compile("phishing", []string{
	// Phishing emails
	`(?i)\b(write|compose|draft|create|generate)\b.{0,30}\b(phishing|spear.?phishing)\b`,
	`(?i)\b(write|compose|draft|create|generate)\b.{0,30}\b(scam|fraud(ulent)?)\s+(email|message|letter|text|sms)\b`,
	// Impersonation for fraud
	`(?i)\b(write|compose|draft|create|generate)\b.{0,30}\b(pretend|impersonat|pos(e|ing)\s+as)\b.{0,30}\b(bank|company|support|admin|helpdesk|IT\s+department|CEO|executive|manager)\b`,
	// Fake pages/sites
	`(?i)\b(create|build|clone|replicate|copy)\b.{0,30}\b(fake|phishing|fraudulent)\s+(login|website|page|portal|site|form)\b`,
	`(?i)\b(clone|replicate|copy|mirror)\b.{0,30}\b(login\s+page|website|portal)\b.{0,30}\b(harvest|capture|steal|collect)\b`,
	// Social engineering scripts
	`(?i)\b(write|create|generate)\b.{0,30}\b(social\s+engineering|pretexting|vishing|smishing)\b.{0,30}\b(script|message|call)\b`,
	// Deceptive urgency patterns
	`(?i)\b(write|generate)\b.{0,30}\b(urgent|immediate\s+action|account\s+suspended|verify\s+your\s+(identity|account))\b.{0,30}\b(email|message)\b`,
	// Fake invoices/documents
	`(?i)\b(create|generate|forge)\b.{0,30}\b(fake|forged|fraudulent)\s+(invoice|receipt|document|certificate|ID|badge)\b`,
})

// --- Role Impersonation Patterns ---

var RoleImpersonationPatterns = compile("role_impersonation", []string{
	// Direct role assumption with authority
	`(?i)\b(act|behave|respond|operate|function)\s+(as|like)\s+(a|an|the)\s+(bank|financial|medical|government|police|law\s+enforcement|admin|system\s*admin|database\s*admin|IT|security|support)\b`,
	`(?i)\b(you\s+are|assume\s+the\s+role|take\s+on\s+the\s+role|pretend\s+(to\s+be|you\s+are))\s+(a|an|the)\s+\w+\s*(agent|representative|employee|officer|admin|operator|analyst|technician)\b`,
	// Pretend to have access
	`(?i)\b(pretend|assume|imagine|act\s+as\s+if)\b.{0,30}\b(you\s+have|with)\s+(access\s+to|permission|authorization|clearance|root|admin|elevated)\b`,
	// System identity claims
	`(?i)\b(you\s+are|act\s+as)\s+(a\s+)?(root\s+user|superuser|administrator|sysadmin|DBA|network\s+admin)\b`,
	// Roleplay with sensitive context
	`(?i)\b(roleplay|role.play|RP)\b.{0,30}\b(hack|breach|steal|exfiltrate|break\s+into|infiltrate)\b`,
	// Assume access to customer/patient/user data
	`(?i)\b(you\s+have\s+access|you\s+can\s+access|you\s+can\s+see|you\s+can\s+view)\b.{0,30}\b(customer|patient|user|client|employee|citizen)\s+(data|record|file|info|account|detail)\b`,
})

// --- Data Exfiltration Patterns ---

var ExfiltrationPatterns = compile("exfiltration", []string{
	// Send data to external services
	`(?i)\b(send|post|upload|transmit|forward|exfiltrate|transfer)\b.{0,40}\b(pastebin|paste\.ee|hastebin|ghostbin|dpaste|ix\.io|0x0\.st)\b`,
	`(?i)\b(send|post|upload|transmit|forward|exfiltrate|transfer)\b.{0,40}\b(webhook|discord|telegram|slack)\b.{0,20}\b(hook|bot|channel|api)\b`,
	// Encode and send
	`(?i)\b(base64|encode|encrypt|compress|zip|tar)\b.{0,30}\b(send|post|upload|transmit|exfiltrate)\b`,
	`(?i)\b(send|post|upload|transmit|exfiltrate)\b.{0,30}\b(base64|encod|encrypt|compress)\b`,
	// DNS/HTTP exfiltration
	`(?i)\b(DNS|HTTP|HTTPS|ICMP)\s+(exfiltrat|tunnel|covert\s+channel)\b`,
	`(?i)\b(exfiltrate|extract|steal|siphon|smuggle)\b.{0,30}\b(data|file|database|record|credential|secret|key|token)\b`,
	// Steganography
	`(?i)\b(hide|embed|conceal)\b.{0,30}\b(data|payload|message|file)\b.{0,30}\b(image|picture|photo|audio|video|PDF)\b`,
	// Piping data out
	`(?i)\b(pipe|redirect|dump)\b.{0,30}\b(output|data|result|content)\b.{0,30}\b(remote|external|server|endpoint|URL)\b`,
	// Collect and exfil
	`(?i)\b(collect|gather|harvest|scrape|dump)\b.{0,30}\b(send|upload|post|transmit)\b`,
})

// --- Harm / Violence / Weapons Patterns ---

var HarmPatterns = compile("harm", []string{
	// Weapons / explosives
	`(?i)\b(how\s+to|instructions?\s+for|guide\s+to|steps?\s+to|teach\s+me)\b.{0,30}\b(make|build|create|construct|assemble|manufacture|synthesize)\b.{0,30}\b(bomb|explosive|IED|grenade|detonator|incendiary)\b`,
	`(?i)\b(how\s+to|instructions?\s+for|guide\s+to)\b.{0,30}\b(make|build|create|synthesize|manufacture)\b.{0,30}\b(poison|toxin|nerve\s+agent|chemical\s+weapon|biological\s+weapon)\b`,
	`(?i)\b(how\s+to|instructions?\s+for)\b.{0,30}\b(make|build|modify|convert)\b.{0,30}\b(gun|firearm|weapon|silencer|suppressor)\b`,
	`(?i)\b(thermite|napalm|ricin|sarin|mustard\s+gas|chlorine\s+gas|ANFO|TATP|RDX|C-?4)\b.{0,30}\b(recipe|synth|make|create|produce)\b`,
	`(?i)\b(recipe|synth|make|create|produce)\b.{0,30}\b(thermite|napalm|ricin|sarin|mustard\s+gas|chlorine\s+gas|ANFO|TATP|RDX|C-?4)\b`,
	// Harm to people
	`(?i)\b(how\s+to|ways?\s+to|methods?\s+(to|for)|guide\s+to)\b.{0,30}\b(kill|murder|assassinate|poison|harm|injure|hurt|torture|kidnap|abduct)\b.{0,20}\b(someone|person|people|him|her|them)\b`,
	// Self-harm (for safety)
	`(?i)\b(how\s+to|ways?\s+to|methods?\s+(to|for))\b.{0,20}\b(commit\s+suicide|kill\s+(myself|yourself)|end\s+(my|your)\s+life|self.harm)\b`,
	// Drug synthesis
	`(?i)\b(how\s+to|instructions?\s+for|guide\s+to)\b.{0,30}\b(synthe[sz]i[zs]e|cook|make|produce|manufacture)\b.{0,30}\b(meth|methamphetamine|fentanyl|heroin|cocaine|LSD|MDMA|ecstasy)\b`,
	// Swatting / harassment
	`(?i)\b(how\s+to|guide\s+to)\b.{0,20}\b(swat|dox|doxx|stalk|harass|threaten|blackmail|extort)\b`,
})

// --- Obfuscation / Evasion Patterns ---

var ObfuscationPatterns = compile("obfuscation", []string{
	// Base64 decode + execute patterns
	`(?i)\b(decode|decrypt)\b.{0,20}\b(base64|b64)\b.{0,30}\b(execute|run|eval|follow|obey|comply)\b`,
	`(?i)\b(execute|run|eval|follow|obey|comply)\b.{0,30}\b(decoded|decrypted|base64|b64)\b`,
	// Encoded payloads (actual base64 strings > 20 chars that look suspicious)
	`(?i)\b(decode|interpret|translate|convert)\s+(this|the\s+following)\b.{0,10}(base64|encoded|encrypted|rot13|hex)`,
	// ROT13 / cipher evasion
	`(?i)\b(rot13|rot-13|caesar\s+cipher|caesar\s+shift)\b.{0,30}\b(decode|decrypt|translate|decipher|interpret)\b`,
	// Character splitting evasion ("ig nore prev ious")
	`(?i)i\s*g\s*n\s*o\s*r\s*e.{0,5}p\s*r\s*e\s*v\s*i\s*o\s*u\s*s`,
	`(?i)d\s*i\s*s\s*r\s*e\s*g\s*a\s*r\s*d.{0,5}r\s*u\s*l\s*e\s*s`,
	// Unicode / homoglyph evasion
	`(?i)\b(use|try|with)\s+(unicode|homoglyph|zero.width|invisible\s+character|lookalike)\b`,
	// Hex-encoded instructions
	`(?i)\b(decode|interpret|run|execute)\b.{0,20}\b(hex|hexadecimal|0x)\b`,
	// Prompt wrapping / nesting
	`(?i)\b(wrap|nest|embed|hide|conceal)\b.{0,20}\b(prompt|instruction|command|payload)\b.{0,20}\b(inside|within|in)\b`,
	// Token smuggling
	`(?i)\b(token|character)\s+(smuggl|split|fragment|break\s+up)\b`,
	// Multi-language evasion
	`(?i)\b(translate|say)\s+(this|the\s+following)\s+(in|to)\s+(another\s+language|a\s+different\s+language)\b.{0,20}\b(then|and)\s+(execute|follow|obey)\b`,
})

// --- Injection Patterns ---

var InjectionPatterns = compile("injection", []string{
	// Ignore instructions
	`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|directions|context)`,
	// Disregard rules
	`(?i)disregard\s+(your|all|any|the)\s+(rules|guidelines|instructions|policies|restrictions|constraints)`,
	// Forget safety
	`(?i)forget\s+(your|all|any|the)\s+(safety|content|guard|filter|moderation|rules)`,
	// DAN/jailbreak
	`(?i)you\s+are\s+now\s+(DAN|jailbreak|unrestricted|unfiltered|evil)`,
	// Do Anything Now
	`(?i)\bDAN\b.*\bDo\s+Anything\s+Now\b`,
	// System prompt tags
	`(?i)<\s*(system|admin|root|developer)\s*>`,
	// BEGIN SYSTEM PROMPT
	`(?i)BEGIN\s+(SYSTEM|ADMIN|ROOT)\s+PROMPT`,
	// New instructions override
	`(?i)new\s+(system\s+)?instructions?\s*:`,
	// Pretend/act as
	`(?i)(pretend|act\s+as\s+if)\s+you\s+(have\s+no|don'?t\s+have|are\s+without)\s+(restrictions|limits|rules|filters)`,
	// Override
	`(?i)(override|bypass|disable|turn\s+off)\s+(safety|content|guard|filter|moderation|restriction)`,
})

// --- Shell Command Patterns ---

var ShellCommandPatterns = compile("shell_commands", []string{
	// Destructive commands
	`\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+|--force\s+)`,
	`\brm\s+-[a-zA-Z]*r[a-zA-Z]*f`,
	`\bchmod\s+777\b`,
	`\bmkfs\b`,
	`\bdd\s+if=`,
	// Piped execution from network
	`(?i)\bcurl\b.*\|\s*(ba)?sh`,
	`(?i)\bwget\b.*\|\s*(ba)?sh`,
	`(?i)\bcurl\b.*\|\s*python`,
	`(?i)\bwget\b.*\|\s*python`,
	// Privilege escalation
	`\bsudo\s+`,
	`\bsu\s+-`,
	`\bsu\s+root\b`,
	// Network tools
	`\bnmap\b`,
	`\btcpdump\b`,
	`\bnetcat\b`,
	`\b(nc)\s+-[a-zA-Z]*l`,
	// Reverse shells
	`(?i)/dev/(tcp|udp)/`,
	`(?i)\bbash\s+-i\s+>`,
	// Fork bombs
	`:\(\)\s*\{\s*:\|:\s*&\s*\}`,
})

// --- File Path Patterns ---

var FilePathPatterns = compile("file_paths", []string{
	// Unix absolute paths
	`(?:/(?:etc|var|usr|home|root|opt|tmp|proc|sys|dev)/[\w./_-]+)`,
	// Home-relative paths
	`~/[\w./_-]+`,
	// Dotfile-relative paths
	`\./[\w./_-]+`,
	// Windows paths
	`[A-Z]:\\[\w.\\ _-]+`,
})

// SensitivePathPatterns matches paths that target sensitive files.
var SensitivePathPatterns = compile("sensitive_paths", []string{
	`(?i)/etc/(passwd|shadow|sudoers|hosts)`,
	`(?i)\.ssh/`,
	`(?i)\.gnupg/`,
	`(?i)\.env\b`,
	`(?i)(secret|password|credential|token)s?(\.\w+)?$`,
	`(?i)/root/`,
	`(?i)\.(pem|key|crt|cer|p12|pfx)\b`,
})

// --- URL Patterns ---

var URLPatterns = compile("urls", []string{
	`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`,
})

// --- Code Patterns ---

var CodePatterns = compile("code", []string{
	// Function/method definitions
	`(?i)\b(func|function|def|class|import|require|include|package)\b`,
	// Common code constructs
	`(?i)\b(for|while|if|else|return|var|let|const|int|string|bool)\b.*[{;]`,
	// Code blocks in markdown
	"(?s)```[a-zA-Z]*\\n.*```",
	// Shell-like commands with flags
	`\b\w+\s+(-{1,2}[a-zA-Z][\w-]*)`,
})

// --- Domain extraction (not a boolean check, just extraction) ---

var DomainExtractPattern = regexp.MustCompile(`(?i)(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})`)

// --- Shell command extraction ---

var CommandExtractPatterns = compile("command_extract", []string{
	`\b(rm\s+-[a-zA-Z]+\s+\S+)`,
	`\b(chmod\s+\d+\s+\S+)`,
	`\b(curl\s+\S+)`,
	`\b(wget\s+\S+)`,
	`\b(sudo\s+\S+(?:\s+\S+)*)`,
	`\b(nmap\s+\S+)`,
	`\b(dd\s+if=\S+)`,
	`\b(mkfs\S*)`,
	`\b(nc\s+-\S+)`,
	`\b(netcat\s+\S+)`,
	`\b(tcpdump\s+\S+)`,
})
