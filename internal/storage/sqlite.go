package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Store manages persistent multi-tenant SentinelMesh state in SQLite WAL mode.
type Store struct {
	db *sql.DB
}

// Open initializes a SQLite WAL database at dsn (use ":memory:" for ephemeral tests).
func Open(dsn string) (*Store, error) {
	if dsn == "" {
		dsn = "sentinelmesh.db"
	}
	connStr := dsn
	if !strings.Contains(dsn, ":memory:") && !strings.Contains(dsn, "?") {
		connStr = dsn + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if strings.Contains(dsn, ":memory:") {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(4)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database connection pool.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB exposes underlying sql.DB for integrity verification or read-only checks.
func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL,
			role TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			disabled INTEGER NOT NULL DEFAULT 0,
			failed_logins INTEGER NOT NULL DEFAULT 0,
			locked_until TEXT,
			created_at TEXT NOT NULL,
			last_login_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS enrollment_tokens (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			label TEXT NOT NULL,
			created_by TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			max_uses INTEGER NOT NULL DEFAULT 1,
			used_count INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS agents (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			hostname TEXT NOT NULL,
			os TEXT NOT NULL,
			arch TEXT NOT NULL,
			version TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			status TEXT NOT NULL,
			cpu_percent REAL NOT NULL DEFAULT 0,
			memory_used_mb REAL NOT NULL DEFAULT 0,
			memory_total_mb REAL NOT NULL DEFAULT 0,
			agent_rss_mb REAL NOT NULL DEFAULT 0,
			quarantined INTEGER NOT NULL DEFAULT 0,
			policy_version INTEGER NOT NULL DEFAULT 1,
			labels_json TEXT NOT NULL DEFAULT '{}',
			hmac_secret TEXT NOT NULL,
			registered_at TEXT NOT NULL,
			last_heartbeat TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id, last_heartbeat);`,
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			host TEXT NOT NULL,
			os TEXT NOT NULL,
			category TEXT NOT NULL,
			action TEXT NOT NULL,
			severity TEXT NOT NULL,
			occurred_at TEXT NOT NULL,
			ingested_at TEXT NOT NULL,
			summary TEXT NOT NULL,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_events_tenant_time ON events(tenant_id, occurred_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_events_agent ON events(tenant_id, agent_id, occurred_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_events_category ON events(tenant_id, category, severity);`,
		`CREATE TABLE IF NOT EXISTS rules (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			name TEXT NOT NULL,
			version INTEGER NOT NULL DEFAULT 1,
			severity TEXT NOT NULL,
			priority INTEGER NOT NULL DEFAULT 50,
			enabled INTEGER NOT NULL DEFAULT 1,
			yaml_spec TEXT NOT NULL,
			false_positives INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			rule_name TEXT NOT NULL,
			rule_version INTEGER NOT NULL,
			agent_id TEXT NOT NULL,
			host TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL,
			priority INTEGER NOT NULL,
			mitre_json TEXT NOT NULL DEFAULT '[]',
			explanation TEXT NOT NULL,
			dedup_key TEXT NOT NULL,
			hit_count INTEGER NOT NULL DEFAULT 1,
			event_ids_json TEXT NOT NULL,
			evidence_json TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			acknowledged_by TEXT NOT NULL DEFAULT '',
			incident_id TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status ON alerts(tenant_id, status, last_seen_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(tenant_id, dedup_key, status);`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			title TEXT NOT NULL,
			summary TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL,
			assignee TEXT NOT NULL DEFAULT '',
			recommendations_json TEXT NOT NULL DEFAULT '[]',
			alert_ids_json TEXT NOT NULL DEFAULT '[]',
			approved_by TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS incident_notes (
			id TEXT PRIMARY KEY,
			incident_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			author TEXT NOT NULL,
			note TEXT NOT NULL,
			evidence_ref TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS iocs (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			type TEXT NOT NULL,
			value TEXT NOT NULL,
			confidence INTEGER NOT NULL,
			severity TEXT NOT NULL,
			source TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(tenant_id, type, value)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_iocs_lookup ON iocs(tenant_id, type, value);`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			actor TEXT NOT NULL,
			actor_role TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT NOT NULL,
			outcome TEXT NOT NULL,
			details TEXT NOT NULL DEFAULT '',
			source_ip TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(tenant_id, created_at DESC);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate sqlite schema: %w", err)
		}
	}
	return nil
}

// CheckIntegrity runs SQLite PRAGMA quick_check.
func (s *Store) CheckIntegrity(ctx context.Context) error {
	var res string
	if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check;`).Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("sqlite integrity check returned %q", res)
	}
	return nil
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(v string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, v)
	return t
}

// CreateUser inserts a new operator user.
func (s *Store) CreateUser(ctx context.Context, u *domain.User) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.TenantID == "" {
		u.TenantID = "default"
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	if !domain.ValidRole(u.Role) {
		return fmt.Errorf("invalid role %q", u.Role)
	}
	disabledInt := 0
	if u.Disabled {
		disabledInt = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users(id, tenant_id, username, email, role, password_hash, disabled, failed_logins, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		u.ID, u.TenantID, u.Username, u.Email, string(u.Role), u.PasswordHash, disabledInt, formatTime(u.CreatedAt),
	)
	return err
}

// GetUserByUsername fetches a user by unique username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, username, email, role, password_hash, disabled, failed_logins, locked_until, created_at, last_login_at
		 FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// ListUsers returns users scoped to tenantID (or all if tenantID == "*").
func (s *Store) ListUsers(ctx context.Context, tenantID string) ([]domain.User, error) {
	query := `SELECT id, tenant_id, username, email, role, password_hash, disabled, failed_logins, locked_until, created_at, last_login_at FROM users`
	var args []any
	if tenantID != "" && tenantID != "*" {
		query += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	query += ` ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(r rowScanner) (*domain.User, error) {
	var u domain.User
	var role string
	var disabled, failed int
	var lockedUntil, createdAt, lastLogin sql.NullString
	if err := r.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &role, &u.PasswordHash, &disabled, &failed, &lockedUntil, &createdAt, &lastLogin); err != nil {
		return nil, err
	}
	u.Role = domain.Role(role)
	u.Disabled = disabled != 0
	u.FailedLogins = failed
	u.CreatedAt = parseTime(createdAt.String)
	if lockedUntil.Valid && lockedUntil.String != "" {
		t := parseTime(lockedUntil.String)
		u.LockedUntil = &t
	}
	if lastLogin.Valid && lastLogin.String != "" {
		t := parseTime(lastLogin.String)
		u.LastLoginAt = &t
	}
	return &u, nil
}

// UpdateUserRole updates role or disabled status.
func (s *Store) UpdateUserRole(ctx context.Context, id string, role domain.Role, disabled bool) error {
	if !domain.ValidRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	d := 0
	if disabled {
		d = 1
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET role = ?, disabled = ? WHERE id = ?`, string(role), d, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RecordLoginAttempt updates failed login counter and account lock state.
func (s *Store) RecordLoginAttempt(ctx context.Context, username string, success bool, lockThreshold int, lockDuration time.Duration) error {
	now := time.Now().UTC()
	if success {
		_, err := s.db.ExecContext(ctx,
			`UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE username = ?`,
			formatTime(now), username)
		return err
	}
	u, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		return err
	}
	fails := u.FailedLogins + 1
	var locked sql.NullString
	if lockThreshold > 0 && fails >= lockThreshold {
		locked = sql.NullString{String: formatTime(now.Add(lockDuration)), Valid: true}
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET failed_logins = ?, locked_until = ? WHERE username = ?`, fails, locked, username)
	return err
}

// CreateEnrollmentToken persists a hashed agent enrollment token.
func (s *Store) CreateEnrollmentToken(ctx context.Context, t *domain.EnrollmentToken) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if t.TenantID == "" {
		t.TenantID = "default"
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	if t.MaxUses <= 0 {
		t.MaxUses = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO enrollment_tokens(id, tenant_id, token_hash, label, created_by, expires_at, max_uses, used_count, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.TenantID, t.TokenHash, t.Label, t.CreatedBy, formatTime(t.ExpiresAt), t.MaxUses, t.UsedCount, formatTime(t.CreatedAt),
	)
	return err
}

// ConsumeEnrollmentToken verifies token hash, expiration, and atomically consumes a usage slot.
func (s *Store) ConsumeEnrollmentToken(ctx context.Context, tokenHash string, now time.Time) (*domain.EnrollmentToken, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var t domain.EnrollmentToken
	var exp, created string
	err = tx.QueryRowContext(ctx,
		`SELECT id, tenant_id, token_hash, label, created_by, expires_at, max_uses, used_count, created_at
		 FROM enrollment_tokens WHERE token_hash = ?`, tokenHash,
	).Scan(&t.ID, &t.TenantID, &t.TokenHash, &t.Label, &t.CreatedBy, &exp, &t.MaxUses, &t.UsedCount, &created)
	if err != nil {
		return nil, err
	}
	t.ExpiresAt = parseTime(exp)
	t.CreatedAt = parseTime(created)
	if now.After(t.ExpiresAt) {
		return nil, errors.New("enrollment token expired")
	}
	if t.UsedCount >= t.MaxUses {
		return nil, errors.New("enrollment token exhausted")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_count = used_count + 1 WHERE id = ?`, t.ID); err != nil {
		return nil, err
	}
	t.UsedCount++
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &t, nil
}

// UpsertAgent registers or refreshes an endpoint agent.
func (s *Store) UpsertAgent(ctx context.Context, a *domain.Agent) error {
	now := time.Now().UTC()
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if a.TenantID == "" {
		a.TenantID = "default"
	}
	if a.RegisteredAt.IsZero() {
		a.RegisteredAt = now
	}
	if a.LastHeartbeat.IsZero() {
		a.LastHeartbeat = now
	}
	if a.Status == "" {
		a.Status = "online"
	}
	if a.PolicyVersion <= 0 {
		a.PolicyVersion = 1
	}
	labelsJSON, _ := json.Marshal(a.Labels)
	q := 0
	if a.Quarantined {
		q = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agents(id, tenant_id, hostname, os, arch, version, ip_address, status, cpu_percent, memory_used_mb, memory_total_mb, agent_rss_mb, quarantined, policy_version, labels_json, hmac_secret, registered_at, last_heartbeat)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname=excluded.hostname,
			os=excluded.os,
			arch=excluded.arch,
			version=excluded.version,
			ip_address=excluded.ip_address,
			status=excluded.status,
			cpu_percent=excluded.cpu_percent,
			memory_used_mb=excluded.memory_used_mb,
			memory_total_mb=excluded.memory_total_mb,
			agent_rss_mb=excluded.agent_rss_mb,
			labels_json=excluded.labels_json,
			last_heartbeat=excluded.last_heartbeat`,
		a.ID, a.TenantID, a.Hostname, a.OS, a.Arch, a.Version, a.IPAddress, a.Status,
		a.CPUPercent, a.MemoryUsedMB, a.MemoryTotalMB, a.AgentRSSMB, q, a.PolicyVersion,
		string(labelsJSON), a.HMACSecret, formatTime(a.RegisteredAt), formatTime(a.LastHeartbeat),
	)
	return err
}

// GetAgent fetches an agent including HMACSecret for verification.
func (s *Store) GetAgent(ctx context.Context, agentID string) (*domain.Agent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, hostname, os, arch, version, ip_address, status, cpu_percent, memory_used_mb, memory_total_mb, agent_rss_mb, quarantined, policy_version, labels_json, hmac_secret, registered_at, last_heartbeat
		 FROM agents WHERE id = ?`, agentID)
	return scanAgent(row)
}

// ListAgents returns agents for a tenant with dynamically computed online/degraded/offline status.
func (s *Store) ListAgents(ctx context.Context, tenantID string, now time.Time) ([]domain.Agent, error) {
	query := `SELECT id, tenant_id, hostname, os, arch, version, ip_address, status, cpu_percent, memory_used_mb, memory_total_mb, agent_rss_mb, quarantined, policy_version, labels_json, hmac_secret, registered_at, last_heartbeat FROM agents`
	var args []any
	if tenantID != "" && tenantID != "*" {
		query += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	query += ` ORDER BY last_heartbeat DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		if a.Quarantined {
			a.Status = "quarantined"
		} else {
			age := now.Sub(a.LastHeartbeat)
			switch {
			case age <= 45*time.Second:
				a.Status = "online"
			case age <= 180*time.Second:
				a.Status = "degraded"
			default:
				a.Status = "offline"
			}
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func scanAgent(r rowScanner) (*domain.Agent, error) {
	var a domain.Agent
	var q int
	var labelsJSON, reg, hb string
	if err := r.Scan(&a.ID, &a.TenantID, &a.Hostname, &a.OS, &a.Arch, &a.Version, &a.IPAddress, &a.Status,
		&a.CPUPercent, &a.MemoryUsedMB, &a.MemoryTotalMB, &a.AgentRSSMB, &q, &a.PolicyVersion, &labelsJSON, &a.HMACSecret, &reg, &hb); err != nil {
		return nil, err
	}
	a.Quarantined = q != 0
	_ = json.Unmarshal([]byte(labelsJSON), &a.Labels)
	a.RegisteredAt = parseTime(reg)
	a.LastHeartbeat = parseTime(hb)
	return &a, nil
}

// UpdateAgentHeartbeat records fresh host telemetry metrics.
func (s *Store) UpdateAgentHeartbeat(ctx context.Context, agentID string, cpu, memUsed, memTotal, rss float64, ip string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET cpu_percent = ?, memory_used_mb = ?, memory_total_mb = ?, agent_rss_mb = ?, ip_address = COALESCE(NULLIF(?, ''), ip_address), last_heartbeat = ?, status = 'online' WHERE id = ?`,
		cpu, memUsed, memTotal, rss, ip, formatTime(time.Now().UTC()), agentID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetAgentQuarantine sets or clears endpoint quarantine mode and bumps policy version.
func (s *Store) SetAgentQuarantine(ctx context.Context, tenantID, agentID string, quarantined bool) error {
	q := 0
	if quarantined {
		q = 1
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET quarantined = ?, policy_version = policy_version + 1 WHERE id = ? AND tenant_id = ?`,
		q, agentID, tenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// InsertEventsBatch inserts multiple events inside a single WAL transaction.
func (s *Store) InsertEventsBatch(ctx context.Context, events []domain.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO events(id, tenant_id, agent_id, host, os, category, action, severity, occurred_at, ingested_at, summary, payload_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ev := range events {
		payload, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx,
			ev.ID, ev.TenantID, ev.AgentID, ev.Host, ev.OS, string(ev.Category), ev.Action, string(ev.Severity),
			formatTime(ev.OccurredAt), formatTime(ev.IngestedAt), ev.Summary, string(payload),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// EventQuery defines search and pagination parameters for events.
type EventQuery struct {
	TenantID string
	AgentID  string
	Category string
	Severity string
	Query    string
	Limit    int
	Offset   int
}

// QueryEvents retrieves matching telemetry events ordered newest first.
func (s *Store) QueryEvents(ctx context.Context, q EventQuery) ([]domain.Event, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	var conds []string
	var args []any
	if q.TenantID != "" && q.TenantID != "*" {
		conds = append(conds, `tenant_id = ?`)
		args = append(args, q.TenantID)
	}
	if q.AgentID != "" {
		conds = append(conds, `agent_id = ?`)
		args = append(args, q.AgentID)
	}
	if q.Category != "" {
		conds = append(conds, `category = ?`)
		args = append(args, q.Category)
	}
	if q.Severity != "" {
		conds = append(conds, `severity = ?`)
		args = append(args, q.Severity)
	}
	if q.Query != "" {
		conds = append(conds, `(summary LIKE ? OR payload_json LIKE ? OR host LIKE ?)`)
		like := "%" + q.Query + "%"
		args = append(args, like, like, like)
	}
	sqlStr := `SELECT payload_json FROM events`
	if len(conds) > 0 {
		sqlStr += ` WHERE ` + strings.Join(conds, ` AND `)
	}
	sqlStr += ` ORDER BY occurred_at DESC LIMIT ? OFFSET ?`
	args = append(args, q.Limit, q.Offset)

	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Event
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ev domain.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// EnforceRetention deletes events older than maxAge or exceeding maxRows per tenant.
func (s *Store) EnforceRetention(ctx context.Context, maxAge time.Duration, maxRows int) (int64, error) {
	var totalDeleted int64
	if maxAge > 0 {
		cutoff := formatTime(time.Now().UTC().Add(-maxAge))
		res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE occurred_at < ?`, cutoff)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		totalDeleted += n
	}
	if maxRows > 0 {
		res, err := s.db.ExecContext(ctx,
			`DELETE FROM events WHERE id IN (
				SELECT id FROM events ORDER BY occurred_at DESC LIMIT -1 OFFSET ?
			)`, maxRows)
		if err != nil {
			return totalDeleted, err
		}
		n, _ := res.RowsAffected()
		totalDeleted += n
	}
	return totalDeleted, nil
}

// StoredRule represents a persisted detection rule definition.
type StoredRule struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Name           string    `json:"name"`
	Version        int       `json:"version"`
	Severity       string    `json:"severity"`
	Priority       int       `json:"priority"`
	Enabled        bool      `json:"enabled"`
	YAMLSpec       string    `json:"yaml_spec"`
	FalsePositives int       `json:"false_positives"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// UpsertRule stores or updates a versioned YAML detection rule.
func (s *Store) UpsertRule(ctx context.Context, r *StoredRule) error {
	if r.TenantID == "" {
		r.TenantID = "default"
	}
	if r.UpdatedAt.IsZero() {
		r.UpdatedAt = time.Now().UTC()
	}
	enabledInt := 0
	if r.Enabled {
		enabledInt = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rules(id, tenant_id, name, version, severity, priority, enabled, yaml_spec, false_positives, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name,
			version=rules.version + 1,
			severity=excluded.severity,
			priority=excluded.priority,
			enabled=excluded.enabled,
			yaml_spec=excluded.yaml_spec,
			updated_at=excluded.updated_at`,
		r.ID, r.TenantID, r.Name, r.Version, r.Severity, r.Priority, enabledInt, r.YAMLSpec, r.FalsePositives, formatTime(r.UpdatedAt),
	)
	return err
}

// ListRules retrieves rules for a tenant.
func (s *Store) ListRules(ctx context.Context, tenantID string) ([]StoredRule, error) {
	query := `SELECT id, tenant_id, name, version, severity, priority, enabled, yaml_spec, false_positives, updated_at FROM rules`
	var args []any
	if tenantID != "" && tenantID != "*" {
		query += ` WHERE (tenant_id = ? OR tenant_id = 'default')`
		args = append(args, tenantID)
	}
	query += ` ORDER BY priority DESC, id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredRule
	for rows.Next() {
		var r StoredRule
		var enabled int
		var upd string
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Version, &r.Severity, &r.Priority, &enabled, &r.YAMLSpec, &r.FalsePositives, &upd); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		r.UpdatedAt = parseTime(upd)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertOrDedupAlert inserts a new alert or merges hits into an active dedup_key within the suppression window.
func (s *Store) UpsertOrDedupAlert(ctx context.Context, a *domain.Alert, dedupWindow time.Duration) (bool, error) {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if a.TenantID == "" {
		a.TenantID = "default"
	}
	if a.Status == "" {
		a.Status = domain.AlertOpen
	}
	if a.HitCount <= 0 {
		a.HitCount = 1
	}
	if a.DedupKey != "" && dedupWindow > 0 {
		cutoff := formatTime(a.LastSeenAt.Add(-dedupWindow))
		var existingID, eventIDsRaw string
		err := s.db.QueryRowContext(ctx,
			`SELECT id, event_ids_json FROM alerts
			 WHERE tenant_id = ? AND dedup_key = ? AND status IN ('open', 'acknowledged') AND last_seen_at >= ?
			 ORDER BY last_seen_at DESC LIMIT 1`,
			a.TenantID, a.DedupKey, cutoff,
		).Scan(&existingID, &eventIDsRaw)
		if err == nil {
			var existingIDs []string
			_ = json.Unmarshal([]byte(eventIDsRaw), &existingIDs)
			seen := make(map[string]struct{}, len(existingIDs))
			for _, id := range existingIDs {
				seen[id] = struct{}{}
			}
			for _, id := range a.EventIDs {
				if _, ok := seen[id]; !ok && len(existingIDs) < 100 {
					existingIDs = append(existingIDs, id)
				}
			}
			mergedRaw, _ := json.Marshal(existingIDs)
			_, err := s.db.ExecContext(ctx,
				`UPDATE alerts SET hit_count = hit_count + 1, last_seen_at = ?, event_ids_json = ? WHERE id = ?`,
				formatTime(a.LastSeenAt), string(mergedRaw), existingID)
			a.ID = existingID
			return true, err
		}
	}

	mitreRaw, _ := json.Marshal(a.MITRE)
	evIDsRaw, _ := json.Marshal(a.EventIDs)
	evidenceRaw, _ := json.Marshal(a.Evidence)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts(id, tenant_id, rule_id, rule_name, rule_version, agent_id, host, severity, status, priority, mitre_json, explanation, dedup_key, hit_count, event_ids_json, evidence_json, created_at, last_seen_at, acknowledged_by, incident_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.TenantID, a.RuleID, a.RuleName, a.RuleVersion, a.AgentID, a.Host, string(a.Severity), string(a.Status), a.Priority,
		string(mitreRaw), a.Explanation, a.DedupKey, a.HitCount, string(evIDsRaw), string(evidenceRaw),
		formatTime(a.CreatedAt), formatTime(a.LastSeenAt), a.AcknowledgedBy, a.IncidentID,
	)
	return false, err
}

// ListAlerts returns alerts matching tenant and optional status/severity filters.
func (s *Store) ListAlerts(ctx context.Context, tenantID, status, severity string, limit int) ([]domain.Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var conds []string
	var args []any
	if tenantID != "" && tenantID != "*" {
		conds = append(conds, `tenant_id = ?`)
		args = append(args, tenantID)
	}
	if status != "" {
		conds = append(conds, `status = ?`)
		args = append(args, status)
	}
	if severity != "" {
		conds = append(conds, `severity = ?`)
		args = append(args, severity)
	}
	q := `SELECT id, tenant_id, rule_id, rule_name, rule_version, agent_id, host, severity, status, priority, mitre_json, explanation, dedup_key, hit_count, event_ids_json, evidence_json, created_at, last_seen_at, acknowledged_by, incident_id FROM alerts`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, ` AND `)
	}
	q += ` ORDER BY priority DESC, last_seen_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Alert
	for rows.Next() {
		var a domain.Alert
		var sev, st, mitreRaw, evIDsRaw, evidRaw, created, lastSeen string
		if err := rows.Scan(&a.ID, &a.TenantID, &a.RuleID, &a.RuleName, &a.RuleVersion, &a.AgentID, &a.Host, &sev, &st, &a.Priority,
			&mitreRaw, &a.Explanation, &a.DedupKey, &a.HitCount, &evIDsRaw, &evidRaw, &created, &lastSeen, &a.AcknowledgedBy, &a.IncidentID); err != nil {
			return nil, err
		}
		a.Severity = domain.Severity(sev)
		a.Status = domain.AlertStatus(st)
		_ = json.Unmarshal([]byte(mitreRaw), &a.MITRE)
		_ = json.Unmarshal([]byte(evIDsRaw), &a.EventIDs)
		_ = json.Unmarshal([]byte(evidRaw), &a.Evidence)
		a.CreatedAt = parseTime(created)
		a.LastSeenAt = parseTime(lastSeen)
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateAlertStatus transitions an alert lifecycle state and tracks false positives on its rule.
func (s *Store) UpdateAlertStatus(ctx context.Context, tenantID, alertID string, status domain.AlertStatus, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var ruleID string
	err = tx.QueryRowContext(ctx, `SELECT rule_id FROM alerts WHERE id = ? AND tenant_id = ?`, alertID, tenantID).Scan(&ruleID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE alerts SET status = ?, acknowledged_by = ? WHERE id = ? AND tenant_id = ?`,
		string(status), actor, alertID, tenantID); err != nil {
		return err
	}
	if status == domain.AlertFalsePositive {
		_, _ = tx.ExecContext(ctx, `UPDATE rules SET false_positives = false_positives + 1 WHERE id = ?`, ruleID)
	}
	return tx.Commit()
}

// CreateIncident persists a security incident and associates specified alert IDs.
func (s *Store) CreateIncident(ctx context.Context, inc *domain.Incident) error {
	if inc.ID == "" {
		inc.ID = uuid.NewString()
	}
	if inc.TenantID == "" {
		inc.TenantID = "default"
	}
	now := time.Now().UTC()
	if inc.CreatedAt.IsZero() {
		inc.CreatedAt = now
	}
	inc.UpdatedAt = now
	if inc.Status == "" {
		inc.Status = domain.IncidentOpen
	}
	recsRaw, _ := json.Marshal(inc.Recommendations)
	alertIDsRaw, _ := json.Marshal(inc.AlertIDs)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO incidents(id, tenant_id, title, summary, severity, status, assignee, recommendations_json, alert_ids_json, approved_by, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inc.ID, inc.TenantID, inc.Title, inc.Summary, string(inc.Severity), string(inc.Status), inc.Assignee,
		string(recsRaw), string(alertIDsRaw), inc.ApprovedBy, inc.CreatedBy, formatTime(inc.CreatedAt), formatTime(inc.UpdatedAt),
	); err != nil {
		return err
	}
	for _, aid := range inc.AlertIDs {
		_, _ = tx.ExecContext(ctx, `UPDATE alerts SET incident_id = ? WHERE id = ? AND tenant_id = ?`, inc.ID, aid, inc.TenantID)
	}
	return tx.Commit()
}

// GetIncident fetches a single incident and its investigation notes.
func (s *Store) GetIncident(ctx context.Context, tenantID, incidentID string) (*domain.Incident, []domain.IncidentNote, error) {
	var inc domain.Incident
	var sev, st, recsRaw, alertsRaw, created, updated string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, title, summary, severity, status, assignee, recommendations_json, alert_ids_json, approved_by, created_by, created_at, updated_at
		 FROM incidents WHERE id = ? AND tenant_id = ?`, incidentID, tenantID,
	).Scan(&inc.ID, &inc.TenantID, &inc.Title, &inc.Summary, &sev, &st, &inc.Assignee, &recsRaw, &alertsRaw, &inc.ApprovedBy, &inc.CreatedBy, &created, &updated)
	if err != nil {
		return nil, nil, err
	}
	inc.Severity = domain.Severity(sev)
	inc.Status = domain.IncidentStatus(st)
	_ = json.Unmarshal([]byte(recsRaw), &inc.Recommendations)
	_ = json.Unmarshal([]byte(alertsRaw), &inc.AlertIDs)
	inc.CreatedAt = parseTime(created)
	inc.UpdatedAt = parseTime(updated)

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, incident_id, tenant_id, author, note, evidence_ref, created_at FROM incident_notes WHERE incident_id = ? AND tenant_id = ? ORDER BY created_at ASC`,
		incidentID, tenantID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var notes []domain.IncidentNote
	for rows.Next() {
		var n domain.IncidentNote
		var cAt string
		if err := rows.Scan(&n.ID, &n.IncidentID, &n.TenantID, &n.Author, &n.Note, &n.EvidenceRef, &cAt); err != nil {
			return nil, nil, err
		}
		n.CreatedAt = parseTime(cAt)
		notes = append(notes, n)
	}
	return &inc, notes, rows.Err()
}

// ListIncidents returns tenant incidents ordered by update time.
func (s *Store) ListIncidents(ctx context.Context, tenantID string) ([]domain.Incident, error) {
	query := `SELECT id, tenant_id, title, summary, severity, status, assignee, recommendations_json, alert_ids_json, approved_by, created_by, created_at, updated_at FROM incidents`
	var args []any
	if tenantID != "" && tenantID != "*" {
		query += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	query += ` ORDER BY updated_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Incident
	for rows.Next() {
		var inc domain.Incident
		var sev, st, recsRaw, alertsRaw, created, updated string
		if err := rows.Scan(&inc.ID, &inc.TenantID, &inc.Title, &inc.Summary, &sev, &st, &inc.Assignee, &recsRaw, &alertsRaw, &inc.ApprovedBy, &inc.CreatedBy, &created, &updated); err != nil {
			return nil, err
		}
		inc.Severity = domain.Severity(sev)
		inc.Status = domain.IncidentStatus(st)
		_ = json.Unmarshal([]byte(recsRaw), &inc.Recommendations)
		_ = json.Unmarshal([]byte(alertsRaw), &inc.AlertIDs)
		inc.CreatedAt = parseTime(created)
		inc.UpdatedAt = parseTime(updated)
		out = append(out, inc)
	}
	return out, rows.Err()
}

// UpdateIncident transitions incident status and/or assignment.
func (s *Store) UpdateIncident(ctx context.Context, tenantID, incidentID string, nextStatus domain.IncidentStatus, assignee, approvedBy string) error {
	inc, _, err := s.GetIncident(ctx, tenantID, incidentID)
	if err != nil {
		return err
	}
	if nextStatus != "" && !domain.ValidIncidentTransition(inc.Status, nextStatus) {
		return fmt.Errorf("invalid incident transition %s -> %s", inc.Status, nextStatus)
	}
	if nextStatus == "" {
		nextStatus = inc.Status
	}
	if assignee == "" {
		assignee = inc.Assignee
	}
	if approvedBy == "" {
		approvedBy = inc.ApprovedBy
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE incidents SET status = ?, assignee = ?, approved_by = ?, updated_at = ? WHERE id = ? AND tenant_id = ?`,
		string(nextStatus), assignee, approvedBy, formatTime(time.Now().UTC()), incidentID, tenantID)
	return err
}

// AddIncidentNote attaches an analyst note or evidence link to an incident.
func (s *Store) AddIncidentNote(ctx context.Context, n *domain.IncidentNote) error {
	if n.ID == "" {
		n.ID = uuid.NewString()
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO incident_notes(id, incident_id, tenant_id, author, note, evidence_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.IncidentID, n.TenantID, n.Author, n.Note, n.EvidenceRef, formatTime(n.CreatedAt))
	return err
}

// UpsertIOC stores or refreshes a threat intelligence indicator.
func (s *Store) UpsertIOC(ctx context.Context, ioc *domain.ThreatIndicator) error {
	if ioc.ID == "" {
		ioc.ID = uuid.NewString()
	}
	if ioc.TenantID == "" {
		ioc.TenantID = "default"
	}
	if ioc.CreatedAt.IsZero() {
		ioc.CreatedAt = time.Now().UTC()
	}
	if ioc.ExpiresAt.IsZero() {
		ioc.ExpiresAt = ioc.CreatedAt.Add(30 * 24 * time.Hour)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO iocs(id, tenant_id, type, value, confidence, severity, source, description, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, type, value) DO UPDATE SET
			confidence=excluded.confidence,
			severity=excluded.severity,
			source=excluded.source,
			description=excluded.description,
			expires_at=excluded.expires_at`,
		ioc.ID, ioc.TenantID, string(ioc.Type), strings.ToLower(strings.TrimSpace(ioc.Value)),
		ioc.Confidence, string(ioc.Severity), ioc.Source, ioc.Description, formatTime(ioc.ExpiresAt), formatTime(ioc.CreatedAt),
	)
	return err
}

// ListActiveIOCs returns non-expired indicators for a tenant (or all).
func (s *Store) ListActiveIOCs(ctx context.Context, tenantID string, now time.Time) ([]domain.ThreatIndicator, error) {
	query := `SELECT id, tenant_id, type, value, confidence, severity, source, description, expires_at, created_at FROM iocs WHERE expires_at > ?`
	args := []any{formatTime(now)}
	if tenantID != "" && tenantID != "*" {
		query += ` AND (tenant_id = ? OR tenant_id = 'default')`
		args = append(args, tenantID)
	}
	query += ` ORDER BY confidence DESC, created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ThreatIndicator
	for rows.Next() {
		var i domain.ThreatIndicator
		var t, sev, exp, cr string
		if err := rows.Scan(&i.ID, &i.TenantID, &t, &i.Value, &i.Confidence, &sev, &i.Source, &i.Description, &exp, &cr); err != nil {
			return nil, err
		}
		i.Type = domain.IOCType(t)
		i.Severity = domain.Severity(sev)
		i.ExpiresAt = parseTime(exp)
		i.CreatedAt = parseTime(cr)
		out = append(out, i)
	}
	return out, rows.Err()
}

// AppendAudit records an administrative or security event into the audit log.
func (s *Store) AppendAudit(ctx context.Context, entry domain.AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.TenantID == "" {
		entry.TenantID = "default"
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs(id, tenant_id, actor, actor_role, action, target, outcome, details, source_ip, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.TenantID, entry.Actor, entry.ActorRole, entry.Action, entry.Target, entry.Outcome, entry.Details, entry.SourceIP, formatTime(entry.CreatedAt),
	)
	return err
}

// ListAudit returns latest audit trail records for a tenant.
func (s *Store) ListAudit(ctx context.Context, tenantID string, limit int) ([]domain.AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, tenant_id, actor, actor_role, action, target, outcome, details, source_ip, created_at FROM audit_logs`
	var args []any
	if tenantID != "" && tenantID != "*" {
		query += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditEntry
	for rows.Next() {
		var a domain.AuditEntry
		var cAt string
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Actor, &a.ActorRole, &a.Action, &a.Target, &a.Outcome, &a.Details, &a.SourceIP, &cAt); err != nil {
			return nil, err
		}
		a.CreatedAt = parseTime(cAt)
		out = append(out, a)
	}
	return out, rows.Err()
}

// OverviewStats aggregates real telemetry counts for dashboard overview cards.
type OverviewStats struct {
	TotalEvents      int            `json:"total_events"`
	ActiveAgents     int            `json:"active_agents"`
	TotalAgents      int            `json:"total_agents"`
	OpenAlerts       int            `json:"open_alerts"`
	OpenIncidents    int            `json:"open_incidents"`
	ActiveIOCs       int            `json:"active_iocs"`
	ActiveRules      int            `json:"active_rules"`
	AlertsBySeverity map[string]int `json:"alerts_by_severity"`
	EventsByCategory map[string]int `json:"events_by_category"`
}

// GetOverview computes live SOC dashboard telemetry counts from SQLite.
func (s *Store) GetOverview(ctx context.Context, tenantID string, now time.Time) (*OverviewStats, error) {
	stats := &OverviewStats{
		AlertsBySeverity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
		EventsByCategory: make(map[string]int),
	}
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE tenant_id = ?`, tenantID).Scan(&stats.TotalEvents)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE tenant_id = ? AND status IN ('open','acknowledged')`, tenantID).Scan(&stats.OpenAlerts)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE tenant_id = ? AND status NOT IN ('resolved','closed')`, tenantID).Scan(&stats.OpenIncidents)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM iocs WHERE (tenant_id = ? OR tenant_id = 'default') AND expires_at > ?`, tenantID, formatTime(now)).Scan(&stats.ActiveIOCs)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM rules WHERE (tenant_id = ? OR tenant_id = 'default') AND enabled = 1`, tenantID).Scan(&stats.ActiveRules)

	agents, err := s.ListAgents(ctx, tenantID, now)
	if err == nil {
		stats.TotalAgents = len(agents)
		for _, a := range agents {
			if a.Status == "online" || a.Status == "degraded" {
				stats.ActiveAgents++
			}
		}
	}

	rows, err := s.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM alerts WHERE tenant_id = ? AND status IN ('open','acknowledged') GROUP BY severity`, tenantID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			if err := rows.Scan(&sev, &cnt); err == nil {
				stats.AlertsBySeverity[sev] = cnt
			}
		}
	}

	catRows, err := s.db.QueryContext(ctx, `SELECT category, COUNT(*) FROM events WHERE tenant_id = ? GROUP BY category`, tenantID)
	if err == nil {
		defer catRows.Close()
		for catRows.Next() {
			var cat string
			var cnt int
			if err := catRows.Scan(&cat, &cnt); err == nil {
				stats.EventsByCategory[cat] = cnt
			}
		}
	}
	return stats, nil
}
