package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	scrypto "github.com/fully-ai/sentinelmesh/internal/crypto"
	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/google/uuid"
)

const AgentVersion = "0.1.0"

// Config controls endpoint agent collection and transport behavior.
type Config struct {
	ServerURL      string
	AgentID        string
	TenantID       string
	Hostname       string
	HMACSecret     string
	EnrollToken    string
	SpoolPath      string
	MaxSpoolEvents int
	FIMPaths       []string
	AuthLogPaths   []string
	PersistPaths   []string
	PollInterval   time.Duration
	Labels         map[string]string
}

// HostMetrics summarizes live endpoint resource consumption.
type HostMetrics struct {
	CPUPercent    float64
	MemoryUsedMB  float64
	MemoryTotalMB float64
	AgentRSSMB    float64
	IPAddress     string
}

// OSCollector abstracts Linux/Windows telemetry acquisition.
type OSCollector interface {
	CollectProcesses(ctx context.Context) ([]domain.ProcessInfo, error)
	CollectNetConnections(ctx context.Context) ([]domain.NetworkInfo, error)
	CollectAuthEvents(ctx context.Context) ([]domain.AuthInfo, error)
	CollectServices(ctx context.Context) ([]string, error)
	CollectHostMetrics(ctx context.Context) (HostMetrics, error)
}

// SpoolBuffer stores pending events on disk when the server is unreachable.
type SpoolBuffer struct {
	mu      sync.Mutex
	path    string
	maxSize int
	events  []domain.Event
}

// NewSpoolBuffer loads or initializes a bounded disk spool file.
func NewSpoolBuffer(path string, maxSize int) *SpoolBuffer {
	if maxSize <= 0 {
		maxSize = 5000
	}
	sb := &SpoolBuffer{path: path, maxSize: maxSize}
	if path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(raw, &sb.events)
		}
	}
	return sb
}

// Push appends events up to maxSize (dropping oldest beyond cap) and flushes to disk.
func (s *SpoolBuffer) Push(evs []domain.Event) {
	if len(evs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evs...)
	if len(s.events) > s.maxSize {
		s.events = s.events[len(s.events)-s.maxSize:]
	}
	s.persistLocked()
}

// Drain returns up to limit buffered events without removing them until Ack is called.
func (s *SpoolBuffer) Peek(limit int) []domain.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return nil
	}
	n := limit
	if n <= 0 || n > len(s.events) {
		n = len(s.events)
	}
	out := make([]domain.Event, n)
	copy(out, s.events[:n])
	return out
}

// Ack removes count delivered events from the front of the spool.
func (s *SpoolBuffer) Ack(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if count >= len(s.events) {
		s.events = nil
	} else if count > 0 {
		s.events = s.events[count:]
	}
	s.persistLocked()
}

// Len returns pending buffered event count.
func (s *SpoolBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func (s *SpoolBuffer) persistLocked() {
	if s.path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.path), 0o700)
	data, err := json.Marshal(s.events)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, s.path)
	}
}

// Agent runs OS telemetry collection, FIM diffing, heartbeat sync, and HMAC-signed ingestion.
type Agent struct {
	cfg         Config
	httpClient  *http.Client
	collector   OSCollector
	spool       *SpoolBuffer
	seenPIDs    map[int]string
	fimHashes   map[string]string
	persistHash map[string]string
	mu          sync.Mutex
	PolicyVer   int
	Quarantined bool
}

// New constructs an endpoint agent instance.
func New(cfg Config) *Agent {
	if cfg.Hostname == "" {
		h, _ := os.Hostname()
		if h == "" {
			h = "unknown-host"
		}
		cfg.Hostname = h
	}
	if cfg.TenantID == "" {
		cfg.TenantID = "default"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 15 * time.Second
	}
	return &Agent{
		cfg:         cfg,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		collector:   newOSCollector(cfg.AuthLogPaths),
		spool:       NewSpoolBuffer(cfg.SpoolPath, cfg.MaxSpoolEvents),
		seenPIDs:    make(map[int]string),
		fimHashes:   make(map[string]string),
		persistHash: make(map[string]string),
	}
}

// Credentials returns active enrolled agent identity and HMAC key.
func (a *Agent) Credentials() (agentID, tenantID, hmacSecret string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.AgentID, a.cfg.TenantID, a.cfg.HMACSecret
}

// Register enrolls the agent with SentinelMesh Server using an enrollment token and receives HMAC credentials.
func (a *Agent) Register(ctx context.Context) error {
	if a.cfg.EnrollToken == "" {
		return fmt.Errorf("missing enrollment token")
	}
	metrics, _ := a.collector.CollectHostMetrics(ctx)
	reqBody := map[string]any{
		"token":    a.cfg.EnrollToken,
		"agent_id": a.cfg.AgentID,
		"hostname": a.cfg.Hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"version":  AgentVersion,
		"ip":       metrics.IPAddress,
		"labels":   a.cfg.Labels,
	}
	raw, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.ServerURL+"/api/v1/agents/register", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("register status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AgentID    string `json:"agent_id"`
		TenantID   string `json:"tenant_id"`
		HMACSecret string `json:"hmac_secret"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}
	a.cfg.AgentID = out.AgentID
	a.cfg.TenantID = out.TenantID
	a.cfg.HMACSecret = out.HMACSecret
	return nil
}

// CollectOnce gathers process creations, FIM changes, persistence changes, auth events, and network connections.
func (a *Agent) CollectOnce(ctx context.Context) []domain.Event {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now().UTC()
	var events []domain.Event

	// 1. Process diffing
	if procs, err := a.collector.CollectProcesses(ctx); err == nil {
		nextSeen := make(map[int]string, len(procs))
		initial := len(a.seenPIDs) == 0
		for _, p := range procs {
			sig := p.Name + "|" + p.Cmdline
			nextSeen[p.PID] = sig
			if prev, exists := a.seenPIDs[p.PID]; !exists || prev != sig {
				if initial && len(events) >= 25 {
					continue
				}
				pc := p
				events = append(events, domain.Event{
					ID:         uuid.NewString(),
					TenantID:   a.cfg.TenantID,
					AgentID:    a.cfg.AgentID,
					Host:       a.cfg.Hostname,
					OS:         runtime.GOOS,
					Category:   domain.CategoryProcess,
					Action:     "started",
					Severity:   domain.SeverityInfo,
					OccurredAt: now,
					IngestedAt: now,
					Summary:    fmt.Sprintf("Process started: %s (pid=%d, user=%s)", p.Name, p.PID, p.User),
					Process:    &pc,
				})
			}
		}
		a.seenPIDs = nextSeen
	}

	// 2. File Integrity Monitoring (FIM)
	events = append(events, a.scanFileSet(a.cfg.FIMPaths, a.fimHashes, domain.CategoryFile, now)...)

	// 3. Persistence paths monitoring
	events = append(events, a.scanFileSet(a.cfg.PersistPaths, a.persistHash, domain.CategoryPersistence, now)...)

	// 4. Authentication events
	if auths, err := a.collector.CollectAuthEvents(ctx); err == nil {
		for _, au := range auths {
			copyAu := au
			sev := domain.SeverityInfo
			if au.Outcome == "failure" {
				sev = domain.SeverityLow
			}
			events = append(events, domain.Event{
				ID:         uuid.NewString(),
				TenantID:   a.cfg.TenantID,
				AgentID:    a.cfg.AgentID,
				Host:       a.cfg.Hostname,
				OS:         runtime.GOOS,
				Category:   domain.CategoryAuth,
				Action:     "auth_" + au.Outcome,
				Severity:   sev,
				OccurredAt: now,
				IngestedAt: now,
				Summary:    fmt.Sprintf("Auth %s for user=%s from %s (%s)", au.Outcome, au.User, au.SourceIP, au.Service),
				Auth:       &copyAu,
			})
		}
	}

	// 5. Passive socket connections (bounded sample per cycle)
	if conns, err := a.collector.CollectNetConnections(ctx); err == nil {
		limit := len(conns)
		if limit > 30 {
			limit = 30
		}
		for i := 0; i < limit; i++ {
			c := conns[i]
			events = append(events, domain.Event{
				ID:         uuid.NewString(),
				TenantID:   a.cfg.TenantID,
				AgentID:    a.cfg.AgentID,
				Host:       a.cfg.Hostname,
				OS:         runtime.GOOS,
				Category:   domain.CategoryNetwork,
				Action:     "socket_snapshot",
				Severity:   domain.SeverityInfo,
				OccurredAt: now,
				IngestedAt: now,
				Summary:    fmt.Sprintf("%s %s:%d -> %s:%d (%s)", c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, c.State),
				Network:    &c,
			})
		}
	}

	return events
}

func (a *Agent) scanFileSet(paths []string, cache map[string]string, category domain.EventCategory, now time.Time) []domain.Event {
	var out []domain.Event
	if len(paths) == 0 {
		return out
	}
	initial := len(cache) == 0
	found := make(map[string]string)

	for _, root := range paths {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > 16*1024*1024 {
				return nil
			}
			hash, err := hashFileSHA256(path)
			if err != nil {
				return nil
			}
			found[path] = hash
			prev, seen := cache[path]
			if !seen && !initial {
				out = append(out, makeFileEvent(a.cfg, category, "created", path, hash, "", info.Size(), now))
			} else if seen && prev != hash {
				out = append(out, makeFileEvent(a.cfg, category, "modified", path, hash, prev, info.Size(), now))
			}
			return nil
		})
	}
	if !initial {
		for path, prev := range cache {
			if _, still := found[path]; !still {
				out = append(out, makeFileEvent(a.cfg, category, "deleted", path, "", prev, 0, now))
				delete(cache, path)
			}
		}
	}
	for p, h := range found {
		cache[p] = h
	}
	return out
}

func makeFileEvent(cfg Config, cat domain.EventCategory, action, path, sha, prevSHA string, size int64, now time.Time) domain.Event {
	sev := domain.SeverityMedium
	if cat == domain.CategoryPersistence {
		sev = domain.SeverityHigh
	}
	return domain.Event{
		ID:         uuid.NewString(),
		TenantID:   cfg.TenantID,
		AgentID:    cfg.AgentID,
		Host:       cfg.Hostname,
		OS:         runtime.GOOS,
		Category:   cat,
		Action:     action,
		Severity:   sev,
		OccurredAt: now,
		IngestedAt: now,
		Summary:    fmt.Sprintf("%s %s: %s", cat, action, path),
		File: &domain.FileInfo{
			Path:       path,
			Action:     action,
			SHA256:     sha,
			PrevSHA256: prevSHA,
			Size:       size,
		},
	}
}

func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 16*1024*1024)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SendHeartbeat posts signed host metrics and syncs agent policy state.
func (a *Agent) SendHeartbeat(ctx context.Context) error {
	metrics, err := a.collector.CollectHostMetrics(ctx)
	if err != nil {
		metrics = HostMetrics{}
	}
	payload := map[string]any{
		"cpu_percent":     metrics.CPUPercent,
		"memory_used_mb":  metrics.MemoryUsedMB,
		"memory_total_mb": metrics.MemoryTotalMB,
		"agent_rss_mb":    metrics.AgentRSSMB,
		"ip_address":      metrics.IPAddress,
	}
	raw, _ := json.Marshal(payload)
	respBytes, status, err := a.signedPost(ctx, "/api/v1/agents/heartbeat", raw)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("heartbeat failed status %d: %s", status, string(respBytes))
	}
	var res struct {
		PolicyVersion int  `json:"policy_version"`
		Quarantined   bool `json:"quarantined"`
	}
	if json.Unmarshal(respBytes, &res) == nil {
		a.PolicyVer = res.PolicyVersion
		a.Quarantined = res.Quarantined
	}
	return nil
}

// ShipEvents sends events (and drains offline disk spool) via HMAC-signed batch ingestion.
func (a *Agent) ShipEvents(ctx context.Context, fresh []domain.Event) error {
	if len(fresh) > 0 {
		a.spool.Push(fresh)
	}
	for {
		batch := a.spool.Peek(100)
		if len(batch) == 0 {
			return nil
		}
		raw, err := json.Marshal(map[string]any{"events": batch})
		if err != nil {
			return err
		}
		respBytes, status, err := a.signedPost(ctx, "/api/v1/ingest", raw)
		if err != nil {
			return err
		}
		if status >= 300 {
			return fmt.Errorf("ingest status %d: %s", status, string(respBytes))
		}
		a.spool.Ack(len(batch))
	}
}

func (a *Agent) signedPost(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	if a.cfg.AgentID == "" || a.cfg.HMACSecret == "" {
		return nil, 0, fmt.Errorf("agent not registered")
	}
	ts := fmt.Sprintf("%d", time.Now().UTC().Unix())
	nonce, err := scrypto.GenerateRandomHex(12)
	if err != nil {
		return nil, 0, err
	}
	sig := scrypto.SignAgentRequest(a.cfg.HMACSecret, http.MethodPost, path, ts, nonce, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.ServerURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Agent-ID", a.cfg.AgentID)
	req.Header.Set("X-Sentinel-Timestamp", ts)
	req.Header.Set("X-Sentinel-Nonce", nonce)
	req.Header.Set("X-Sentinel-Signature", sig)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return respBytes, resp.StatusCode, nil
}
