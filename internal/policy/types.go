package policy

// Action represents the action to take when a rule matches.
type Action string

const (
	ActionAllow       Action = "ALLOW"
	ActionDeny        Action = "DENY"
	ActionLog         Action = "LOG"
	ActionModify      Action = "MODIFY"
	ActionQuarantine  Action = "QUARANTINE"
	ActionHumanReview Action = "HUMAN_REVIEW"
	ActionRateLimit   Action = "RATE_LIMIT"
	ActionRedirect    Action = "REDIRECT"
)

// MatchType represents the type of match operation for a condition.
type MatchType string

const (
	MatchExact     MatchType = "exact"
	MatchPrefix    MatchType = "prefix"
	MatchGlob      MatchType = "glob"
	MatchRegex     MatchType = "regex"
	MatchRange     MatchType = "range"
	MatchContains  MatchType = "contains"
	MatchBoolean   MatchType = "boolean"
	MatchThreshold MatchType = "threshold"
)

// MatchCondition is a single match predicate in a rule.
type MatchCondition struct {
	Field     string    `yaml:"field" json:"field"`
	MatchType MatchType `yaml:"match_type" json:"match_type"`
	Value     any       `yaml:"value" json:"value"`
	Negate    bool      `yaml:"negate,omitempty" json:"negate,omitempty"`
}

// GuardRule is a single firewall-style rule with priority, conditions, and action.
type GuardRule struct {
	Name        string           `yaml:"name" json:"name"`
	Description string           `yaml:"description" json:"description"`
	Priority    int              `yaml:"priority" json:"priority"`
	Action      Action           `yaml:"action" json:"action"`
	DenyMessage string           `yaml:"deny_message,omitempty" json:"deny_message,omitempty"`
	Conditions  []MatchCondition `yaml:"conditions" json:"conditions"`
}

// RateLimits configures rate limiting thresholds.
type RateLimits struct {
	RequestsPerMinute int `yaml:"requests_per_minute" json:"requests_per_minute"`
	RequestsPerHour   int `yaml:"requests_per_hour" json:"requests_per_hour"`
	BurstThreshold    int `yaml:"burst_threshold" json:"burst_threshold"`
}

// NetworkPolicy configures allowed/denied domains.
type NetworkPolicy struct {
	EgressPolicy   string   `yaml:"egress_policy" json:"egress_policy"`
	AllowedDomains []string `yaml:"allowed_domains" json:"allowed_domains"`
	DeniedDomains  []string `yaml:"denied_domains" json:"denied_domains"`
}

// FilesystemPolicy configures allowed/denied file paths.
type FilesystemPolicy struct {
	DeniedPaths       []string `yaml:"denied_paths" json:"denied_paths"`
	AllowedReadPaths  []string `yaml:"allowed_read_paths" json:"allowed_read_paths"`
	AllowedWritePaths []string `yaml:"allowed_write_paths" json:"allowed_write_paths"`
}

// Policy is the top-level policy configuration loaded from YAML.
type Policy struct {
	Version       string           `yaml:"version" json:"version"`
	PolicyName    string           `yaml:"policy_name" json:"policy_name"`
	DefaultAction Action           `yaml:"default_action" json:"default_action"`
	IngressRules  []GuardRule      `yaml:"ingress_rules" json:"ingress_rules"`
	EgressRules   []GuardRule      `yaml:"egress_rules" json:"egress_rules"`
	RateLimits    RateLimits       `yaml:"rate_limits" json:"rate_limits"`
	Network       NetworkPolicy    `yaml:"network" json:"network"`
	Filesystem    FilesystemPolicy `yaml:"filesystem" json:"filesystem"`
}

// MatchActionTable holds a sorted list of rules and a default action.
type MatchActionTable struct {
	Rules         []GuardRule
	DefaultAction Action
}

// RuleResult captures which rule matched and what action was taken.
type RuleResult struct {
	Matched     bool   `json:"matched"`
	RuleName    string `json:"rule_name,omitempty"`
	Action      Action `json:"action"`
	DenyMessage string `json:"deny_message,omitempty"`
}
