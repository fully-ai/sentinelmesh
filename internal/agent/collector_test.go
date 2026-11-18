package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
)

func TestSpoolBufferAndFIMCollection(t *testing.T) {
	dir := t.TempDir()
	spoolPath := filepath.Join(dir, "spool.json")

	sb := NewSpoolBuffer(spoolPath, 3)
	sb.Push([]domain.Event{
		{ID: "1", AgentID: "a", Category: domain.CategoryProcess, Action: "started"},
		{ID: "2", AgentID: "a", Category: domain.CategoryProcess, Action: "started"},
		{ID: "3", AgentID: "a", Category: domain.CategoryProcess, Action: "started"},
		{ID: "4", AgentID: "a", Category: domain.CategoryProcess, Action: "started"},
	})
	if sb.Len() != 3 {
		t.Fatalf("expected capped spool len 3, got %d", sb.Len())
	}

	// Reload from disk and verify bounded order preserved
	sb2 := NewSpoolBuffer(spoolPath, 3)
	peeked := sb2.Peek(2)
	if len(peeked) != 2 || peeked[0].ID != "2" {
		t.Fatalf("unexpected reloaded spool: %+v", peeked)
	}
	sb2.Ack(2)
	if sb2.Len() != 1 {
		t.Fatalf("expected remaining 1 event, got %d", sb2.Len())
	}

	// FIM baseline + modification detection
	fimDir := filepath.Join(dir, "watched")
	if err := os.MkdirAll(fimDir, 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(fimDir, "critical.conf")
	if err := os.WriteFile(target, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	ag := New(Config{
		AgentID:  "a1",
		FIMPaths: []string{fimDir},
	})
	_ = ag.CollectOnce(context.Background()) // Initial baseline

	if err := os.WriteFile(target, []byte("v2-modified"), 0o600); err != nil {
		t.Fatal(err)
	}
	evs := ag.CollectOnce(context.Background())
	foundMod := false
	for _, ev := range evs {
		if ev.Category == domain.CategoryFile && ev.File != nil && ev.File.Action == "modified" && ev.File.Path == target {
			foundMod = true
		}
	}
	if !foundMod {
		t.Fatalf("expected FIM modification event for %s, got %+v", target, evs)
	}
}

func TestLinuxCollectorMetrics(t *testing.T) {
	col := newOSCollector(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	procs, err := col.CollectProcesses(ctx)
	if err != nil || len(procs) == 0 {
		t.Fatalf("expected live process list, got err=%v len=%d", err, len(procs))
	}
	metrics, err := col.CollectHostMetrics(ctx)
	if err != nil || metrics.MemoryTotalMB <= 0 {
		t.Fatalf("expected host memory metrics, got err=%v metrics=%+v", err, metrics)
	}
}
