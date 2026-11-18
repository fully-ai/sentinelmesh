package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	scrypto "github.com/fully-ai/sentinelmesh/internal/crypto"
	"github.com/fully-ai/sentinelmesh/internal/detection"
	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/fully-ai/sentinelmesh/internal/netmon"
	"github.com/fully-ai/sentinelmesh/internal/pipeline"
	"github.com/fully-ai/sentinelmesh/internal/plugin"
	"github.com/fully-ai/sentinelmesh/internal/storage"
	"github.com/fully-ai/sentinelmesh/internal/threatintel"
	"github.com/google/uuid"
)

// ServerConfig configures SentinelMesh REST API security and operational controls.
type ServerConfig struct {
	JWTSecret       []byte
	AllowDisruptive bool
	RetentionMaxAge time.Duration
	RetentionMaxRow int
	WebFS           embed.FS
}

// Server exposes authenticated REST endpoints, agent ingestion, and the embedded SOC dashboard.
type Server struct {
	store     *storage.Store
	pipe      *pipeline.Pipeline
	engine    *detection.Engine
	iocs      *threatintel.Matcher
	plugins   *plugin.Runner
	cfg       ServerConfig
	nonces    *scrypto.NonceCache
	limiter   *RateLimiter
	mux       *http.ServeMux
	webServer http.Handler
}

// NewServer constructs a configured HTTP handler ready to mount on net/http.
func NewServer(store *storage.Store, pipe *pipeline.Pipeline, engine *detection.Engine, iocs *threatintel.Matcher, plugins *plugin.Runner, cfg ServerConfig) *Server {
	if len(cfg.JWTSecret) < 16 {
		panic("JWTSecret must be at least 16 bytes")
	}
	s := &Server{
		store:   store,
		pipe:    pipe,
		engine:  engine,
		iocs:    iocs,
		plugins: plugins,
		cfg:     cfg,
		nonces:  scrypto.NewNonceCache(5*time.Minute, 50000),
		limiter: NewRateLimiter(30, 90),
		mux:     http.NewServeMux(),
	}
	if sub, err := fs.Sub(cfg.WebFS, "web"); err == nil {
		s.webServer = http.FileServer(http.FS(sub))
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")

	if !strings.HasPrefix(r.URL.Path, "/api/") && s.webServer != nil {
		s.webServer.ServeHTTP(w, r)
		return
	}
	if !s.limiter.Allow(clientIP(r), time.Now().UTC()) {
		w.Header().Set("Retry-After", "2")
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("GET /api/v1/auth/me", s.requireAuth("read", s.handleMe))

	// Agent enrollment & signed telemetry
	s.mux.HandleFunc("POST /api/v1/agents/tokens", s.requireAuth("agent:enroll", s.handleCreateEnrollToken))
	s.mux.HandleFunc("POST /api/v1/agents/register", s.handleAgentRegister)
	s.mux.HandleFunc("POST /api/v1/agents/heartbeat", s.handleAgentHeartbeat)
	s.mux.HandleFunc("POST /api/v1/ingest", s.handleIngest)

	// Operator & SOC APIs
	s.mux.HandleFunc("GET /api/v1/overview", s.requireAuth("read", s.handleOverview))
	s.mux.HandleFunc("GET /api/v1/agents", s.requireAuth("read", s.handleListAgents))
	s.mux.HandleFunc("POST /api/v1/agents/{id}/quarantine", s.requireAuth("quarantine", s.handleQuarantineAgent))
	s.mux.HandleFunc("GET /api/v1/events", s.requireAuth("read", s.handleListEvents))
	s.mux.HandleFunc("GET /api/v1/alerts", s.requireAuth("read", s.handleListAlerts))
	s.mux.HandleFunc("POST /api/v1/alerts/{id}/status", s.requireAuth("alert:ack", s.handleUpdateAlertStatus))

	s.mux.HandleFunc("GET /api/v1/incidents", s.requireAuth("read", s.handleListIncidents))
	s.mux.HandleFunc("POST /api/v1/incidents", s.requireAuth("incident:create", s.handleCreateIncident))
	s.mux.HandleFunc("GET /api/v1/incidents/{id}", s.requireAuth("read", s.handleGetIncident))
	s.mux.HandleFunc("PATCH /api/v1/incidents/{id}", s.requireAuth("incident:transition", s.handleUpdateIncident))
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/notes", s.requireAuth("incident:note", s.handleAddIncidentNote))

	s.mux.HandleFunc("GET /api/v1/rules", s.requireAuth("read", s.handleListRules))
	s.mux.HandleFunc("POST /api/v1/rules", s.requireAuth("rule:write", s.handleUpsertRule))
	s.mux.HandleFunc("POST /api/v1/rules/test", s.requireAuth("investigate", s.handleTestRule))

	s.mux.HandleFunc("GET /api/v1/iocs", s.requireAuth("read", s.handleListIOCs))
	s.mux.HandleFunc("POST /api/v1/iocs", s.requireAuth("ioc:write", s.handleUpsertIOC))
	s.mux.HandleFunc("POST /api/v1/iocs/import", s.requireAuth("ioc:write", s.handleImportIOCs))
	s.mux.HandleFunc("GET /api/v1/iocs/export", s.requireAuth("read", s.handleExportIOCs))

	s.mux.HandleFunc("POST /api/v1/network/pcap", s.requireAuth("pcap:analyze", s.handleAnalyzePCAP))

	s.mux.HandleFunc("GET /api/v1/users", s.requireAuth("user:manage", s.handleListUsers))
	s.mux.HandleFunc("POST /api/v1/users", s.requireAuth("user:manage", s.handleCreateUser))
	s.mux.HandleFunc("PATCH /api/v1/users/{id}", s.requireAuth("user:manage", s.handleUpdateUser))
	s.mux.HandleFunc("GET /api/v1/audit", s.requireAuth("read", s.handleListAudit))
	s.mux.HandleFunc("GET /api/v1/plugins", s.requireAuth("read", s.handleListPlugins))
	s.mux.HandleFunc("POST /api/v1/plugins/{id}/test", s.requireAuth("plugin:run", s.handleTestPlugin))
	s.mux.HandleFunc("GET /api/v1/settings", s.requireAuth("read", s.handleGetSettings))
	s.mux.HandleFunc("POST /api/v1/settings/retention", s.requireAuth("settings:write", s.handleRunRetention))
}

type ctxKey string

const claimsKey ctxKey = "claims"

func getClaims(r *http.Request) *scrypto.TokenClaims {
	c, _ := r.Context().Value(claimsKey).(*scrypto.TokenClaims)
	return c
}

func resolveTenant(r *http.Request, c *scrypto.TokenClaims) string {
	if c == nil {
		return "default"
	}
	if domain.Role(c.Role) == domain.RoleAdmin {
		if reqTenant := strings.TrimSpace(r.URL.Query().Get("tenant_id")); reqTenant != "" {
			return reqTenant
		}
	}
	if c.TenantID != "" {
		return c.TenantID
	}
	return "default"
}

func (s *Server) requireAuth(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHdr, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tok := strings.TrimPrefix(authHdr, "Bearer ")
		claims, err := scrypto.VerifyToken(s.cfg.JWTSecret, tok, time.Now().UTC())
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		if !domain.CanPerform(domain.Role(claims.Role), permission) {
			writeErr(w, http.StatusForbidden, "insufficient permissions for "+permission)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	dbOK := s.store.CheckIntegrity(r.Context()) == nil
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"db_ok":    dbOK,
		"pipeline": s.pipe.Stats(),
		"time":     time.Now().UTC(),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body, 16*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := s.store.GetUserByUsername(r.Context(), strings.TrimSpace(body.Username))
	if err != nil || user.Disabled {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	now := time.Now().UTC()
	if user.LockedUntil != nil && now.Before(*user.LockedUntil) {
		writeErr(w, http.StatusLocked, "account temporarily locked after repeated failures")
		return
	}
	if !scrypto.VerifyPassword(body.Password, user.PasswordHash) {
		_ = s.store.RecordLoginAttempt(r.Context(), user.Username, false, 5, 10*time.Minute)
		_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
			TenantID: user.TenantID, Actor: user.Username, ActorRole: string(user.Role),
			Action: "auth.login", Target: user.Username, Outcome: "failure", SourceIP: clientIP(r),
		})
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	_ = s.store.RecordLoginAttempt(r.Context(), user.Username, true, 5, 10*time.Minute)
	token, err := scrypto.SignToken(s.cfg.JWTSecret, scrypto.TokenClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Role:      string(user.Role),
		TenantID:  user.TenantID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(12 * time.Hour).Unix(),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token issuance error")
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: user.TenantID, Actor: user.Username, ActorRole: string(user.Role),
		Action: "auth.login", Target: user.Username, Outcome: "success", SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  user,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, getClaims(r))
}

func (s *Server) handleCreateEnrollToken(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	var body struct {
		Label    string `json:"label"`
		MaxUses  int    `json:"max_uses"`
		TTLHours int    `json:"ttl_hours"`
		TenantID string `json:"tenant_id"`
	}
	if err := decodeJSON(r, &body, 16*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rawTok, err := scrypto.GenerateRandomHex(24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ttl := 24 * time.Hour
	if body.TTLHours > 0 && body.TTLHours <= 720 {
		ttl = time.Duration(body.TTLHours) * time.Hour
	}
	tenant := resolveTenant(r, claims)
	if body.TenantID != "" && domain.Role(claims.Role) == domain.RoleAdmin {
		tenant = body.TenantID
	}
	tokRec := domain.EnrollmentToken{
		ID:        uuid.NewString(),
		TenantID:  tenant,
		TokenHash: scrypto.SHA256Hex([]byte(rawTok)),
		Label:     body.Label,
		CreatedBy: claims.Username,
		MaxUses:   body.MaxUses,
		ExpiresAt: time.Now().UTC().Add(ttl),
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateEnrollmentToken(r.Context(), &tokRec); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: tenant, Actor: claims.Username, ActorRole: claims.Role,
		Action: "agent.token.create", Target: tokRec.ID, Outcome: "success", Details: body.Label, SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      rawTok,
		"id":         tokRec.ID,
		"tenant_id":  tenant,
		"expires_at": tokRec.ExpiresAt,
		"max_uses":   tokRec.MaxUses,
	})
}

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string            `json:"token"`
		AgentID  string            `json:"agent_id"`
		Hostname string            `json:"hostname"`
		OS       string            `json:"os"`
		Arch     string            `json:"arch"`
		Version  string            `json:"version"`
		IP       string            `json:"ip"`
		Labels   map[string]string `json:"labels"`
	}
	if err := decodeJSON(r, &body, 32*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Token == "" || body.Hostname == "" {
		writeErr(w, http.StatusBadRequest, "token and hostname required")
		return
	}
	tok, err := s.store.ConsumeEnrollmentToken(r.Context(), scrypto.SHA256Hex([]byte(body.Token)), time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	secret, err := scrypto.GenerateRandomHex(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	agentID := body.AgentID
	if agentID == "" {
		agentID = uuid.NewString()
	}
	ip := body.IP
	if ip == "" {
		ip = clientIP(r)
	}
	ag := domain.Agent{
		ID:            agentID,
		TenantID:      tok.TenantID,
		Hostname:      body.Hostname,
		OS:            body.OS,
		Arch:          body.Arch,
		Version:       body.Version,
		IPAddress:     ip,
		Status:        "online",
		PolicyVersion: 1,
		Labels:        body.Labels,
		HMACSecret:    secret,
		RegisteredAt:  time.Now().UTC(),
		LastHeartbeat: time.Now().UTC(),
	}
	if err := s.store.UpsertAgent(r.Context(), &ag); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: tok.TenantID, Actor: "agent:" + agentID, ActorRole: "agent",
		Action: "agent.register", Target: ag.Hostname, Outcome: "success", SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"agent_id":    ag.ID,
		"tenant_id":   ag.TenantID,
		"hmac_secret": secret,
	})
}

func (s *Server) authenticateAgent(r *http.Request, body []byte) (*domain.Agent, error) {
	agentID := r.Header.Get("X-Sentinel-Agent-ID")
	if agentID == "" {
		return nil, errors.New("missing X-Sentinel-Agent-ID header")
	}
	ag, err := s.store.GetAgent(r.Context(), agentID)
	if err != nil {
		return nil, errors.New("unknown agent")
	}
	err = scrypto.VerifyAgentRequest(
		ag.HMACSecret,
		r.Method,
		r.URL.Path,
		r.Header.Get("X-Sentinel-Timestamp"),
		r.Header.Get("X-Sentinel-Nonce"),
		r.Header.Get("X-Sentinel-Signature"),
		body,
		time.Now().UTC(),
		s.nonces,
	)
	if err != nil {
		return nil, err
	}
	return ag, nil
}

func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ag, err := s.authenticateAgent(r, raw)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	var hb struct {
		CPUPercent    float64 `json:"cpu_percent"`
		MemoryUsedMB  float64 `json:"memory_used_mb"`
		MemoryTotalMB float64 `json:"memory_total_mb"`
		AgentRSSMB    float64 `json:"agent_rss_mb"`
		IPAddress     string  `json:"ip_address"`
	}
	if err := json.Unmarshal(raw, &hb); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid heartbeat payload")
		return
	}
	if err := s.store.UpdateAgentHeartbeat(r.Context(), ag.ID, hb.CPUPercent, hb.MemoryUsedMB, hb.MemoryTotalMB, hb.AgentRSSMB, hb.IPAddress); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"policy_version": ag.PolicyVersion,
		"quarantined":    ag.Quarantined,
	})
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ag, err := s.authenticateAgent(r, raw)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	var payload struct {
		Events []domain.Event `json:"events"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid events batch JSON")
		return
	}
	for i := range payload.Events {
		// Enforce server-authenticated agent/tenant identity to defeat spoofing.
		payload.Events[i].AgentID = ag.ID
		payload.Events[i].TenantID = ag.TenantID
		if payload.Events[i].Host == "" {
			payload.Events[i].Host = ag.Hostname
		}
	}
	if err := s.pipe.Enqueue(payload.Events); err != nil {
		if errors.Is(err, pipeline.ErrQueueFull) {
			w.Header().Set("Retry-After", "3")
			writeErr(w, http.StatusTooManyRequests, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted": len(payload.Events),
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	stats, err := s.store.GetOverview(r.Context(), tenant, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"overview": stats,
		"pipeline": s.pipe.Stats(),
		"tenant":   tenant,
	})
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	agents, err := s.store.ListAgents(r.Context(), tenant, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

func (s *Server) handleQuarantineAgent(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowDisruptive {
		writeErr(w, http.StatusForbidden, "disruptive response actions are disabled by server policy (set ALLOW_DISRUPTIVE_RESPONSE=true)")
		return
	}
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	agentID := r.PathValue("id")
	var body struct {
		Quarantined bool   `json:"quarantined"`
		Reason      string `json:"reason"`
	}
	if err := decodeJSON(r, &body, 8*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SetAgentQuarantine(r.Context(), tenant, agentID, body.Quarantined); err != nil {
		writeErr(w, http.StatusNotFound, "agent not found")
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: tenant, Actor: claims.Username, ActorRole: claims.Role,
		Action: "agent.quarantine", Target: agentID, Outcome: "success",
		Details:  "quarantined=" + strconv.FormatBool(body.Quarantined) + " reason=" + body.Reason,
		SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": agentID, "quarantined": body.Quarantined})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	events, err := s.store.QueryEvents(r.Context(), storage.EventQuery{
		TenantID: tenant,
		AgentID:  r.URL.Query().Get("agent_id"),
		Category: r.URL.Query().Get("category"),
		Severity: r.URL.Query().Get("severity"),
		Query:    r.URL.Query().Get("q"),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	alerts, err := s.store.ListAlerts(r.Context(), tenant, r.URL.Query().Get("status"), r.URL.Query().Get("severity"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

func (s *Server) handleUpdateAlertStatus(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	alertID := r.PathValue("id")
	var body struct {
		Status domain.AlertStatus `json:"status"`
	}
	if err := decodeJSON(r, &body, 8*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch body.Status {
	case domain.AlertOpen, domain.AlertAcknowledged, domain.AlertFalsePositive, domain.AlertSuppressed, domain.AlertResolved:
	default:
		writeErr(w, http.StatusBadRequest, "invalid alert status")
		return
	}
	if err := s.store.UpdateAlertStatus(r.Context(), tenant, alertID, body.Status, claims.Username); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: tenant, Actor: claims.Username, ActorRole: claims.Role,
		Action: "alert.status", Target: alertID, Outcome: "success", Details: string(body.Status), SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"id": alertID, "status": body.Status})
}

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	incs, err := s.store.ListIncidents(r.Context(), tenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": incs})
}

func (s *Server) handleCreateIncident(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	var body struct {
		Title           string          `json:"title"`
		Summary         string          `json:"summary"`
		Severity        domain.Severity `json:"severity"`
		Assignee        string          `json:"assignee"`
		AlertIDs        []string        `json:"alert_ids"`
		Recommendations []string        `json:"recommendations"`
	}
	if err := decodeJSON(r, &body, 32*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.Title) == "" {
		writeErr(w, http.StatusBadRequest, "title required")
		return
	}
	if body.Severity == "" {
		body.Severity = domain.SeverityHigh
	}
	inc := domain.Incident{
		ID:              uuid.NewString(),
		TenantID:        tenant,
		Title:           body.Title,
		Summary:         body.Summary,
		Severity:        body.Severity,
		Status:          domain.IncidentOpen,
		Assignee:        body.Assignee,
		Recommendations: body.Recommendations,
		AlertIDs:        body.AlertIDs,
		CreatedBy:       claims.Username,
	}
	if err := s.store.CreateIncident(r.Context(), &inc); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: tenant, Actor: claims.Username, ActorRole: claims.Role,
		Action: "incident.create", Target: inc.ID, Outcome: "success", Details: inc.Title, SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusCreated, inc)
}

func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	inc, notes, err := s.store.GetIncident(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "incident not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"incident": inc, "notes": notes})
}

func (s *Server) handleUpdateIncident(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	id := r.PathValue("id")
	var body struct {
		Status   domain.IncidentStatus `json:"status"`
		Assignee string                `json:"assignee"`
	}
	if err := decodeJSON(r, &body, 8*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	approvedBy := ""
	if body.Status == domain.IncidentContained || body.Status == domain.IncidentResolved {
		approvedBy = claims.Username
	}
	if err := s.store.UpdateIncident(r.Context(), tenant, id, body.Status, body.Assignee, approvedBy); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: tenant, Actor: claims.Username, ActorRole: claims.Role,
		Action: "incident.update", Target: id, Outcome: "success", Details: string(body.Status) + " assignee=" + body.Assignee, SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": body.Status, "assignee": body.Assignee})
}

func (s *Server) handleAddIncidentNote(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	id := r.PathValue("id")
	var body struct {
		Note        string `json:"note"`
		EvidenceRef string `json:"evidence_ref"`
	}
	if err := decodeJSON(r, &body, 32*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.Note) == "" {
		writeErr(w, http.StatusBadRequest, "note required")
		return
	}
	n := domain.IncidentNote{
		IncidentID:  id,
		TenantID:    tenant,
		Author:      claims.Username,
		Note:        body.Note,
		EvidenceRef: body.EvidenceRef,
	}
	if err := s.store.AddIncidentNote(r.Context(), &n); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, n)
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	rules, err := s.store.ListRules(r.Context(), tenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleUpsertRule(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	var body struct {
		YAMLSpec string `json:"yaml_spec"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := decodeJSON(r, &body, 64*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	spec, err := detection.ParseRuleYAML(body.YAMLSpec)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := spec.Enabled
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	rec := storage.StoredRule{
		ID:       spec.ID,
		TenantID: tenant,
		Name:     spec.Name,
		Version:  spec.Version,
		Severity: string(spec.Severity),
		Priority: spec.Priority,
		Enabled:  enabled,
		YAMLSpec: body.YAMLSpec,
	}
	if err := s.store.UpsertRule(r.Context(), &rec); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Reload in-memory detection engine
	if stored, err := s.store.ListRules(r.Context(), "*"); err == nil {
		var specs []*detection.RuleSpec
		for _, sr := range stored {
			if sp, err := detection.ParseRuleYAML(sr.YAMLSpec); err == nil {
				sp.Enabled = sr.Enabled
				sp.Version = sr.Version
				specs = append(specs, sp)
			}
		}
		s.engine.SetRules(specs)
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: tenant, Actor: claims.Username, ActorRole: claims.Role,
		Action: "rule.upsert", Target: spec.ID, Outcome: "success", SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleTestRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAMLSpec string       `json:"yaml_spec"`
		Event    domain.Event `json:"event"`
	}
	if err := decodeJSON(r, &body, 64*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	spec, err := detection.ParseRuleYAML(body.YAMLSpec)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	spec.Enabled = true
	if body.Event.ID == "" {
		body.Event.ID = uuid.NewString()
	}
	if body.Event.OccurredAt.IsZero() {
		body.Event.OccurredAt = time.Now().UTC()
	}
	tmpEngine := detection.NewEngine([]*detection.RuleSpec{spec})
	alerts := tmpEngine.Evaluate(body.Event)
	// Filter out EWMA anomaly alert for rule test endpoint
	var matched []domain.Alert
	for _, a := range alerts {
		if a.RuleID == spec.ID {
			matched = append(matched, a)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matched": len(matched) > 0,
		"alerts":  matched,
	})
}

func (s *Server) handleListIOCs(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	iocs, err := s.store.ListActiveIOCs(r.Context(), tenant, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"iocs": iocs})
}

func (s *Server) handleUpsertIOC(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	var ind domain.ThreatIndicator
	if err := decodeJSON(r, &ind, 16*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if ind.Value == "" || ind.Type == "" {
		writeErr(w, http.StatusBadRequest, "type and value required")
		return
	}
	ind.TenantID = tenant
	if ind.Severity == "" {
		ind.Severity = domain.SeverityHigh
	}
	if ind.Confidence <= 0 {
		ind.Confidence = 80
	}
	if err := s.store.UpsertIOC(r.Context(), &ind); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if active, err := s.store.ListActiveIOCs(r.Context(), "*", time.Now().UTC()); err == nil {
		s.iocs.Reload(active, time.Now().UTC())
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: tenant, Actor: claims.Username, ActorRole: claims.Role,
		Action: "ioc.upsert", Target: string(ind.Type) + ":" + ind.Value, Outcome: "success", SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusCreated, ind)
}

func (s *Server) handleImportIOCs(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	list, err := threatintel.ParseCSV(raw, tenant, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for i := range list {
		_ = s.store.UpsertIOC(r.Context(), &list[i])
	}
	if active, err := s.store.ListActiveIOCs(r.Context(), "*", time.Now().UTC()); err == nil {
		s.iocs.Reload(active, time.Now().UTC())
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": len(list)})
}

func (s *Server) handleExportIOCs(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	active, err := s.store.ListActiveIOCs(r.Context(), tenant, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	data, _ := threatintel.ExportJSON(active)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (s *Server) handleAnalyzePCAP(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	summary, err := netmon.ParsePCAP(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var alerts []domain.Alert
	if r.URL.Query().Get("ingest") == "true" {
		events := netmon.PacketsToEvents(tenant, "pcap-analyzer", "authorized-pcap", summary)
		if len(events) > 0 {
			emitted, err := s.pipe.ProcessSync(r.Context(), events)
			if err == nil {
				alerts = emitted
			}
		}
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: tenant, Actor: claims.Username, ActorRole: claims.Role,
		Action: "network.pcap.analyze", Target: strconv.Itoa(summary.PacketCount) + "_packets", Outcome: "success", SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": summary,
		"alerts":  alerts,
	})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	users, err := s.store.ListUsers(r.Context(), tenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tenant := resolveTenant(r, claims)
	var body struct {
		Username string      `json:"username"`
		Email    string      `json:"email"`
		Role     domain.Role `json:"role"`
		Password string      `json:"password"`
		TenantID string      `json:"tenant_id"`
	}
	if err := decodeJSON(r, &body, 16*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := scrypto.HashPassword(body.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	t := tenant
	if body.TenantID != "" {
		t = body.TenantID
	}
	u := domain.User{
		ID:           uuid.NewString(),
		TenantID:     t,
		Username:     strings.TrimSpace(body.Username),
		Email:        strings.TrimSpace(body.Email),
		Role:         body.Role,
		PasswordHash: hash,
	}
	if err := s.store.CreateUser(r.Context(), &u); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: t, Actor: claims.Username, ActorRole: claims.Role,
		Action: "user.create", Target: u.Username, Outcome: "success", Details: string(u.Role), SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	id := r.PathValue("id")
	var body struct {
		Role     domain.Role `json:"role"`
		Disabled bool        `json:"disabled"`
	}
	if err := decodeJSON(r, &body, 8*1024); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateUserRole(r.Context(), id, body.Role, body.Disabled); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: claims.TenantID, Actor: claims.Username, ActorRole: claims.Role,
		Action: "user.update", Target: id, Outcome: "success", Details: string(body.Role), SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "role": body.Role, "disabled": body.Disabled})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	tenant := resolveTenant(r, getClaims(r))
	logs, err := s.store.ListAudit(r.Context(), tenant, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit_logs": logs})
}

func (s *Server) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	if s.plugins == nil {
		writeJSON(w, http.StatusOK, map[string]any{"plugins": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plugins": s.plugins.List()})
}

func (s *Server) handleTestPlugin(w http.ResponseWriter, r *http.Request) {
	if s.plugins == nil {
		writeErr(w, http.StatusNotFound, "no plugins configured")
		return
	}
	res := s.plugins.InvokeAlert(r.Context(), r.PathValue("id"), domain.Alert{
		ID:       uuid.NewString(),
		RuleID:   "SM-PLUGIN-TEST",
		RuleName: "Controlled Plugin Verification",
		Severity: domain.SeverityInfo,
		Host:     "soc-control-plane",
	})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"allow_disruptive_response": s.cfg.AllowDisruptive,
		"retention_max_age_hours":   int(s.cfg.RetentionMaxAge.Hours()),
		"retention_max_rows":        s.cfg.RetentionMaxRow,
		"pipeline":                  s.pipe.Stats(),
	})
}

func (s *Server) handleRunRetention(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	deleted, err := s.store.EnforceRetention(r.Context(), s.cfg.RetentionMaxAge, s.cfg.RetentionMaxRow)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(r.Context(), domain.AuditEntry{
		TenantID: claims.TenantID, Actor: claims.Username, ActorRole: claims.Role,
		Action: "settings.retention", Target: "events", Outcome: "success",
		Details: "pruned=" + strconv.FormatInt(deleted, 10), SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"pruned_events": deleted})
}

func decodeJSON(r *http.Request, dst any, maxBytes int64) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBytes))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
