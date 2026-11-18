package pipeline

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/detection"
	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/fully-ai/sentinelmesh/internal/storage"
	"github.com/fully-ai/sentinelmesh/internal/threatintel"
)

func TestPipelineBackpressureAndRedaction(t *testing.T) {
	st, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	eng := detection.NewEngine(nil)
	iocs := threatintel.NewMatcher(nil, time.Now().UTC())
	p := New(st, eng, iocs, 2) // Deliberately do not start workers so queue fills

	err = p.Enqueue([]domain.Event{
		{ID: "1", AgentID: "a1", Category: domain.CategoryProcess, Action: "started"},
		{ID: "2", AgentID: "a1", Category: domain.CategoryProcess, Action: "started"},
		{ID: "3", AgentID: "a1", Category: domain.CategoryProcess, Action: "started"},
	})
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("expected ErrQueueFull backpressure, got %v", err)
	}
	if p.Stats().Dropped != 1 {
		t.Fatalf("expected 1 dropped event under backpressure, got %d", p.Stats().Dropped)
	}

	ev := domain.Event{
		ID:       "red-1",
		AgentID:  "a1",
		Category: domain.CategoryProcess,
		Action:   "started",
		Summary:  "curl -H 'Authorization: Bearer mysecrettoken12345' https://api.local",
		Process: &domain.ProcessInfo{
			Cmdline: "tool --api-key=abc123456 --token ghp_supersecretvalue123456",
		},
	}
	RedactSecrets(&ev)
	if ev.Summary != "curl -H 'Authorization: Bearer [REDACTED]' https://api.local" {
		t.Fatalf("unexpected redacted summary: %s", ev.Summary)
	}
	if ev.Process.Cmdline == "tool --api-key=abc123456 --token ghp_supersecretvalue123456" {
		t.Fatalf("expected cmdline secret redaction, got %s", ev.Process.Cmdline)
	}

	_, err = p.ProcessSync(context.Background(), []domain.Event{ev})
	if err != nil {
		t.Fatalf("ProcessSync: %v", err)
	}
}

func BenchmarkPipelineProcessSync(b *testing.B) {
	st, err := storage.Open(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	specs, _, _ := detection.ParseDefaultRules()
	eng := detection.NewEngine(specs)
	p := New(st, eng, threatintel.NewMatcher(nil, time.Now().UTC()), 4096)

	batch := make([]domain.Event, 50)
	now := time.Now().UTC()
	for i := range batch {
		batch[i] = domain.Event{
			ID:         fmt.Sprintf("bench-%d", i),
			TenantID:   "default",
			AgentID:    "a1",
			Host:       "bench-node",
			Category:   domain.CategoryProcess,
			Action:     "started",
			Severity:   domain.SeverityInfo,
			OccurredAt: now,
			Process:    &domain.ProcessInfo{PID: 100 + i, Name: "worker", Cmdline: "/usr/bin/worker --mode=fast"},
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range batch {
			batch[j].ID = fmt.Sprintf("b-%d-%d", i, j)
		}
		if _, err := p.ProcessSync(context.Background(), batch); err != nil {
			b.Fatal(err)
		}
	}
}
