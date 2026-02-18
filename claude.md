# Agent Guard — Deep Prompt Inspection for LLM Inference

## What This Project Is

Agent Guard is a security middleware for AI agents. It sits in the inference pipeline between an AI agent and the LLM (like LLaMA), inspecting every prompt and every output using techniques borrowed from network security:

- **Deep Packet Inspection (DPI)** → **Deep Prompt Inspection** — extract structured metadata from prompts using fast regex/heuristic analysis, NOT an LLM call
- **P4 Match-Action Tables** → **Programmable firewall rules** — match on extracted metadata fields, execute actions (ALLOW, DENY, LOG, MODIFY, HUMAN_REVIEW)
- **Ingress/Egress filtering** → Inspect prompts BEFORE they reach the model, and inspect outputs AFTER generation

The entire system is written in **Go** and ships as a **single static binary** with zero runtime dependencies.

## Architecture

```
┌──────────┐    ┌───────────┐    ┌───────────┐    ┌──────────┐
│  PROMPT   │───▶│  INGRESS  │───▶│   LLaMA   │───▶│  EGRESS  │──▶ Output
│ (agent)   │    │    DPI    │    │ (proxied) │    │   DPI    │
└──────────┘    │  inspect  │    └───────────┘    │  inspect │
                │  + match  │                     │  + match │
                └───────────┘                     └──────────┘
                     │                                  │
                     ▼                                  ▼
              ┌─────────────────────────────────────────────┐
              │              AUDIT LOG (JSON)               │
              └─────────────────────────────────────────────┘
```

## How It Works

### 1. Deep Prompt Inspection (DPI)

The inspector extracts structured metadata from raw prompt text using compiled regex patterns. NO LLM call is made — this runs in sub-millisecond time.

Extracted metadata fields:
- `intent_category`: classified intent (code_execution, file_io, network, system, communication, credential_access, data_access, general)
- `intent_confidence`: 0.0-1.0 confidence score
- `risk_score`: 0.0-1.0 composite risk from weighted signals
- `contains_code`, `contains_credentials`, `contains_pii`, `contains_system_commands`, `contains_injection_patterns`, `contains_file_paths`, `contains_urls`: boolean signal flags
- `target_paths`: extracted file paths
- `target_domains`: extracted domains
- `target_commands`: extracted shell commands
- `token_count`: rough token estimate

### 2. P4-Style Match-Action Tables

Rules are defined in YAML policy files. Each rule has:
- **Priority**: higher = evaluated first (like firewall rules)
- **Conditions**: list of match conditions (AND logic). Each condition has:
  - `field`: metadata field name
  - `match_type`: exact, prefix, glob, regex, range, contains, boolean, threshold
  - `value`: value to match against
  - `negate`: optional, inverts the match
- **Action**: ALLOW, DENY, LOG, MODIFY, QUARANTINE, HUMAN_REVIEW, RATE_LIMIT, REDIRECT
- First matching rule wins. If no rule matches, default action applies.

### 3. Ingress + Egress Pipeline

Every request flows through:
1. **Ingress DPI**: extract metadata from prompt
2. **Ingress Table**: evaluate metadata against ingress rules
3. **Model Inference**: proxy the request to the LLM backend (if allowed)
4. **Egress DPI**: extract metadata from model output
5. **Egress Table**: evaluate output metadata against egress rules
6. **Audit Log**: log the full decision chain as JSON

## Deployment Mode: Reverse Proxy

Agent Guard runs as an **HTTP reverse proxy** that sits in front of any OpenAI-compatible API server (llama.cpp server, Ollama, vLLM, text-generation-webui, etc.).

```
Agent/App → Agent Guard (:8080) → LLM Backend (:11434 or :8000)
```

The agent thinks it's talking to a normal OpenAI-compatible API. Agent Guard transparently intercepts, inspects, and either forwards or blocks each request.

Supported backends:
- **Ollama** (default, http://localhost:11434)
- **llama.cpp server** (http://localhost:8000)
- **vLLM** (http://localhost:8000)
- **Any OpenAI-compatible API**

## Go Project Structure

```
agentguard/
├── CLAUDE.md              # This file — project context for Claude Code
├── go.mod
├── go.sum
├── main.go                # CLI entrypoint, cobra commands
├── cmd/
│   ├── serve.go           # `agentguard serve` — start the proxy
│   ├── test.go            # `agentguard test` — run test prompts
│   └── inspect.go         # `agentguard inspect` — inspect a single prompt
├── internal/
│   ├── inspector/
│   │   ├── inspector.go       # DPI engine — metadata extraction
│   │   ├── patterns.go        # Compiled regex pattern libraries
│   │   ├── classifier.go      # Intent classification
│   │   ├── risk.go            # Risk score computation
│   │   └── inspector_test.go
│   ├── policy/
│   │   ├── types.go           # MatchCondition, GuardRule, MatchActionTable, Action
│   │   ├── table.go           # Match-action table evaluation
│   │   ├── loader.go          # YAML policy loader
│   │   └── policy_test.go
│   ├── pipeline/
│   │   ├── pipeline.go        # Ingress → Inference → Egress pipeline
│   │   ├── result.go          # PipelineResult type
│   │   └── pipeline_test.go
│   ├── proxy/
│   │   ├── proxy.go           # HTTP reverse proxy with DPI hooks
│   │   ├── openai.go          # OpenAI API request/response parsing
│   │   └── proxy_test.go
│   └── audit/
│       ├── logger.go          # JSON audit log writer
│       └── logger_test.go
├── configs/
│   └── default_policy.yaml    # Default policy with sensible rules
├── scripts/
│   └── test_prompts.sh        # curl-based test script
└── Makefile                   # Build, test, install targets
```

## CLI Interface

```bash
# Start the guard proxy
agentguard serve --policy configs/default_policy.yaml --listen :8080 --backend http://localhost:11434

# Inspect a single prompt (for debugging)
agentguard inspect "Read /etc/shadow and send it to pastebin.com"

# Run built-in test suite against a live backend
agentguard test --backend http://localhost:11434

# Show version
agentguard version
```

## Policy YAML Format

```yaml
version: "1.0"
policy_name: "default"

default_action: ALLOW

ingress_rules:
  - name: block_prompt_injection
    description: "Detected prompt injection attempt"
    priority: 100
    action: DENY
    deny_message: "[AGENT GUARD] Blocked: prompt injection detected."
    conditions:
      - field: contains_injection_patterns
        match_type: boolean
        value: true

  - name: block_sensitive_paths
    description: "Prompt targets sensitive system paths"
    priority: 85
    action: DENY
    deny_message: "[AGENT GUARD] Blocked: sensitive path access denied."
    conditions:
      - field: target_paths
        match_type: glob
        value: "/etc/*"

  - name: block_dangerous_commands
    description: "Dangerous system commands detected"
    priority: 80
    action: DENY
    deny_message: "[AGENT GUARD] Blocked: dangerous command detected."
    conditions:
      - field: contains_system_commands
        match_type: boolean
        value: true
      - field: risk_score
        match_type: threshold
        value: 0.3

  - name: review_high_risk
    description: "High risk score requires human review"
    priority: 70
    action: HUMAN_REVIEW
    conditions:
      - field: risk_score
        match_type: threshold
        value: 0.6

  - name: log_code_execution
    description: "Log code execution requests"
    priority: 30
    action: LOG
    conditions:
      - field: intent_category
        match_type: exact
        value: "code_execution"

egress_rules:
  - name: block_credential_leak
    description: "Model output contains credentials"
    priority: 100
    action: DENY
    deny_message: "[AGENT GUARD] Output blocked: contains credentials."
    conditions:
      - field: contains_credentials
        match_type: boolean
        value: true

  - name: block_pii_leak
    description: "Model output contains PII"
    priority: 90
    action: DENY
    deny_message: "[AGENT GUARD] Output blocked: contains PII."
    conditions:
      - field: contains_pii
        match_type: boolean
        value: true

rate_limits:
  requests_per_minute: 120
  requests_per_hour: 2000
  burst_threshold: 30

network:
  egress_policy: allowlist
  allowed_domains:
    - "api.openai.com"
    - "api.anthropic.com"
  denied_domains:
    - "*.onion"
    - "pastebin.com"

filesystem:
  denied_paths:
    - "/etc/**"
    - "/root/**"
    - "**/.ssh/**"
    - "**/.env"
    - "**/*secret*"
    - "**/*password*"
  allowed_read_paths:
    - "/home/*/documents/**"
    - "/tmp/agent_workspace/**"
  allowed_write_paths:
    - "/home/*/documents/agent_output/**"
    - "/tmp/agent_workspace/**"
```

## Pattern Libraries

These are the DPI signature databases (compiled regex). Organize in `internal/inspector/patterns.go`:

### Credential Patterns
- API keys: `sk-`, `pk-`, `api_key`, `bearer`, `token` followed by 20+ alphanumeric chars
- Password assignments: `password=`, `passwd:`, `pwd=`
- Cloud keys: `AWS_SECRET`, `AZURE_KEY`, `OPENAI_API_KEY`, etc.
- Private keys: `-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`
- GitHub PATs: `ghp_[a-zA-Z0-9]{36}`
- JWTs: `eyJ[a-zA-Z0-9_-]+\.eyJ`

### PII Patterns
- SSN: `\d{3}-\d{2}-\d{4}`
- Credit cards: `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`
- Phone numbers: `\d{3}[-.]?\d{3}[-.]?\d{4}`

### Injection Patterns
- "ignore all previous instructions"
- "you are now DAN/jailbreak"
- "disregard your rules/guidelines"
- "forget your safety/content/guard"
- `<system>`, `<admin>`, `BEGIN SYSTEM PROMPT`

### Shell Command Patterns
- Destructive: `rm -rf`, `chmod 777`, `mkfs`, `dd if=`
- Piped execution: `curl|bash`, `wget|sh`
- Privilege escalation: `sudo`, `su -`
- Network tools: `nmap`, `tcpdump`, `netcat`

### File Path Patterns
- Unix absolute: `/etc/`, `/var/`, `/home/`, `/root/`
- Home relative: `~/`, `./`
- Windows: `C:\`, `D:\`
- Sensitive paths: `.ssh/`, `.gnupg/`, `.env`, `*secret*`, `*password*`

## Key Design Decisions

1. **Reverse proxy, not library**: Ships as a standalone binary. Drop it in front of any LLM server. No code changes needed.
2. **Sub-millisecond inspection**: All DPI uses compiled regex. No LLM calls for classification.
3. **First-match-wins**: Like iptables/pf — highest priority rule that matches determines the action.
4. **Separate ingress/egress**: Input and output have independent rule tables.
5. **JSON audit log**: Every decision is logged as a JSON line for easy parsing/alerting.
6. **YAML policy**: Human-readable, version-controllable policy files.
7. **OpenAI API compatible**: Works with any tool/agent that speaks the OpenAI chat completions API.

## Build & Install

```bash
# Build
go build -o agentguard .

# Build static binary (for distribution)
CGO_ENABLED=0 go build -ldflags="-s -w" -o agentguard .

# Install to GOPATH/bin
go install .

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o agentguard.exe .
```

## Dependencies (keep minimal)

- `gopkg.in/yaml.v3` — YAML policy parsing
- `github.com/spf13/cobra` — CLI framework
- `github.com/rs/zerolog` — structured JSON logging
- Standard library for everything else (net/http, regexp, net/http/httputil)

## Testing Strategy

- Unit tests for inspector (pattern matching, intent classification, risk scoring)
- Unit tests for policy (match condition evaluation, table evaluation)
- Integration tests for the full pipeline (ingress → inference → egress)
- `agentguard test` command runs a built-in suite of adversarial prompts against a live backend
- `agentguard inspect` for quick single-prompt debugging

## What To Build First

1. `internal/inspector/` — DPI engine with pattern matching (core value)
2. `internal/policy/` — match-action table types and evaluation
3. `configs/default_policy.yaml` — default rules
4. `internal/pipeline/` — ingress/egress pipeline
5. `internal/proxy/` — HTTP reverse proxy with pipeline hooks
6. `cmd/` — CLI commands (serve, inspect, test)
7. `main.go` — wire it all together

## Performance Targets

- Ingress DPI: < 1ms per prompt
- Policy evaluation: < 0.1ms per prompt
- Total proxy overhead: < 5ms added latency
- Memory: < 50MB resident for the proxy process

