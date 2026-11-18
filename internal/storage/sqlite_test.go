package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
)

func TestStoreLifecycleRetentionAndDedup(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.CheckIntegrity(ctx); err != nil {
		t.Fatalf("CheckIntegrity: %v", err)
	}

	now := time.Now().UTC()
	var batch []domain.Event
	for i := 0; i < 6; i++ {
		batch = append(batch, domain.Event{
			ID:         fmt.Sprintf("ev-%d", i),
			TenantID:   "t1",
			AgentID:    "ag-1",
			Host:       "srv-1",
			Category:   domain.CategoryProcess,
			Action:     "started",
			Severity:   domain.SeverityInfo,
			OccurredAt: now.Add(time.Duration(i) * time.Second),
			IngestedAt: now,
			Summary:    fmt.Sprintf("proc %d", i),
		})
	}
	if err := st.InsertEventsBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	deleted, err := st.EnforceRetention(ctx, 0, 3)
	if err != nil || deleted != 3 {
		t.Fatalf("EnforceRetention maxRows=3: err=%v deleted=%d", err, deleted)
	}

	// Dedup alert merging
	a := domain.Alert{
		TenantID: "t1", RuleID: "R1", RuleName: "Rule1", RuleVersion: 1, AgentID: "ag-1", Host: "srv-1",
		Severity: domain.SeverityHigh, Priority: 80, Explanation: "first", DedupKey: "k1",
		EventIDs: []string{"ev-1"}, CreatedAt: now, LastSeenAt: now,
	}
	merged, err := st.UpsertOrDedupAlert(ctx, &a, 5*time.Minute)
	if err != nil || merged {
		t.Fatalf("first alert unexpected merged=%v err=%v", merged, err)
	}
	a2 := a
	a2.ID = ""
	a2.EventIDs = []string{"ev-2"}
	a2.LastSeenAt = now.Add(10 * time.Second)
	merged2, err := st.UpsertOrDedupAlert(ctx, &a2, 5*time.Minute)
	if err != nil || !merged2 {
		t.Fatalf("second alert expected dedup merge, merged=%v err=%v", merged2, err)
	}
	list, _ := st.ListAlerts(ctx, "t1", "", "", 10)
	if len(list) != 1 || list[0].HitCount != 2 || len(list[0].EventIDs) != 2 {
		t.Fatalf("unexpected merged alert: %+v", list)
	}

	// False positive increment
	if err := st.UpsertRule(ctx, &StoredRule{ID: "R1", TenantID: "t1", Name: "Rule1", Version: 1, Severity: "high", Priority: 80, Enabled: true, YAMLSpec: "id: R1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateAlertStatus(ctx, "t1", list[0].ID, domain.AlertFalsePositive, "analyst"); err != nil {
		t.Fatal(err)
	}
	rules, _ := st.ListRules(ctx, "t1")
	if len(rules) == 0 || rules[0].FalsePositives != 1 {
		t.Fatalf("expected false positive count 1, got %+v", rules)
	}

	ov, err := st.GetOverview(ctx, "t1", now)
	if err != nil || ov.TotalEvents != 3 {
		t.Fatalf("GetOverview: err=%v ov=%+v", err, ov)
	}
}
