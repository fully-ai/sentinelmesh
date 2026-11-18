package detection

import (
	"context"
	"fmt"

	"github.com/fully-ai/sentinelmesh/internal/storage"
)

// DefaultRuleYAMLSpecs returns SentinelMesh's bundled defensive detection & correlation rule library.
var DefaultRuleYAMLSpecs = []string{
	`id: SM-PROC-001
name: Pipe-to-Shell Remote Script Execution
description: Detects curl or wget piped directly into sh/bash/zsh/python.
version: 1
enabled: true
severity: high
priority: 85
mitre: ["T1059.004", "T1105"]
dedup_seconds: 120
all:
  - field: category
    op: equals
    value: process
  - field: process.cmdline
    op: regex
    case_fold: true
    value: '(curl|wget)\s+[^\n|]+\|\s*(sh|bash|zsh|dash|python3?)'
`,
	`id: SM-PROC-002
name: Suspicious Base64 Encoded Command Execution
description: Detects base64 decoding piped to shell or executed in one-liner commands.
version: 1
enabled: true
severity: high
priority: 80
mitre: ["T1027", "T1059"]
dedup_seconds: 120
all:
  - field: category
    op: equals
    value: process
  - field: process.cmdline
    op: regex
    case_fold: true
    value: '(base64\s+(-d|--decode)|frombase64string)'
`,
	`id: SM-FIM-001
name: Critical System File Integrity Modification
description: Alerts when watched system binaries, passwd/sudoers, or preload configs change hash or are written.
version: 1
enabled: true
severity: critical
priority: 95
mitre: ["T1547", "T1574"]
dedup_seconds: 60
all:
  - field: category
    op: equals
    value: file
  - field: file.action
    op: in
    values: ["modified", "created", "deleted"]
  - field: file.path
    op: regex
    value: '(/etc/(passwd|shadow|sudoers|ld\.so\.preload|ssh/sshd_config)|System32)'
`,
	`id: SM-PERSIST-001
name: Unauthorized Persistence Mechanism Added
description: Detects new or modified cron jobs, systemd unit files, authorized_keys, or Windows Run keys.
version: 1
enabled: true
severity: high
priority: 85
mitre: ["T1053", "T1543", "T1547.001"]
dedup_seconds: 120
all:
  - field: category
    op: equals
    value: persistence
  - field: action
    op: in
    values: ["created", "modified", "persistence_detected"]
`,
	`id: SM-AUTH-CORR-001
name: Authentication Brute-Force Threshold
description: Triggers when >= 5 failed authentication events occur from the same source IP within 120 seconds.
version: 1
enabled: true
severity: high
priority: 82
mitre: ["T1110"]
dedup_seconds: 300
all:
  - field: category
    op: equals
    value: auth
  - field: auth.outcome
    op: equals
    value: failure
correlation:
  window_seconds: 120
  threshold: 5
  group_by: ["agent_id", "auth.source_ip"]
`,
	`id: SM-AUTH-SEQ-002
name: Brute Force Failure Followed by Successful Login
description: Sequence rule correlating a failed authentication followed by a successful login for the same user and host within 180s.
version: 1
enabled: true
severity: critical
priority: 92
mitre: ["T1110", "T1078"]
dedup_seconds: 300
correlation:
  window_seconds: 180
  group_by: ["agent_id", "auth.user"]
  sequence:
    - name: auth_failure
      match:
        - field: category
          op: equals
          value: auth
        - field: auth.outcome
          op: equals
          value: failure
    - name: auth_success
      match:
        - field: category
          op: equals
          value: auth
        - field: auth.outcome
          op: equals
          value: success
`,
	`id: SM-NET-001
name: Potential DNS Tunneling High-Entropy Subdomain
description: Flags DNS queries flagged by the network analyzer for excessive label length or high Shannon entropy.
version: 1
enabled: true
severity: medium
priority: 65
mitre: ["T1071.004"]
dedup_seconds: 180
all:
  - field: category
    op: equals
    value: network
  - field: metadata.dns_anomaly
    op: equals
    value: "true"
`,
}

// ParseDefaultRules returns parsed RuleSpecs and YAML text mappings.
func ParseDefaultRules() ([]*RuleSpec, map[string]string, error) {
	specs := make([]*RuleSpec, 0, len(DefaultRuleYAMLSpecs))
	rawMap := make(map[string]string, len(DefaultRuleYAMLSpecs))
	for _, yml := range DefaultRuleYAMLSpecs {
		spec, err := ParseRuleYAML(yml)
		if err != nil {
			return nil, nil, fmt.Errorf("default rule invalid: %w", err)
		}
		specs = append(specs, spec)
		rawMap[spec.ID] = yml
	}
	return specs, rawMap, nil
}

// SeedDefaultRules inserts default rules into Store if missing and returns active parsed specs.
func SeedDefaultRules(ctx context.Context, st *storage.Store) ([]*RuleSpec, error) {
	existing, err := st.ListRules(ctx, "*")
	if err != nil {
		return nil, err
	}
	if len(existing) == 0 {
		specs, rawMap, err := ParseDefaultRules()
		if err != nil {
			return nil, err
		}
		for _, spec := range specs {
			if err := st.UpsertRule(ctx, &storage.StoredRule{
				ID:       spec.ID,
				TenantID: "default",
				Name:     spec.Name,
				Version:  spec.Version,
				Severity: string(spec.Severity),
				Priority: spec.Priority,
				Enabled:  spec.Enabled,
				YAMLSpec: rawMap[spec.ID],
			}); err != nil {
				return nil, err
			}
		}
		return specs, nil
	}
	var out []*RuleSpec
	for _, sr := range existing {
		spec, err := ParseRuleYAML(sr.YAMLSpec)
		if err != nil {
			continue
		}
		spec.Enabled = sr.Enabled
		spec.Version = sr.Version
		out = append(out, spec)
	}
	return out, nil
}
