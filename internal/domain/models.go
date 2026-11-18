package domain

import (
	"fmt"
	"strings"
	"time"
)

// Role defines RBAC access levels across SentinelMesh.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleResponder Role = "responder"
	RoleAnalyst   Role = "analyst"
	RoleViewer    Role = "viewer"
)

// ValidRole returns true when r is a recognized RBAC role.
func ValidRole(r Role) bool {
	switch r {
	case RoleAdmin, RoleResponder, RoleAnalyst, RoleViewer:
		return true
	default:
		return false
	}
}

// CanPerform checks RBAC permissions for high-level capabilities.
func CanPerform(r Role, permission string) bool {
	switch permission {
	case "read":
		return ValidRole(r)
	case "investigate", "alert:ack", "alert:fp", "incident:note", "incident:create", "pcap:analyze":
		return r == RoleAdmin || r == RoleResponder || r == RoleAnalyst
	case "respond", "incident:assign", "incident:transition", "quarantine":
		return r == RoleAdmin || r == RoleResponder
	case "admin", "user:manage", "rule:write", "agent:enroll", "ioc:write", "settings:write", "plugin:run":
		return r == RoleAdmin
	default:
		return false
	}
}

// Severity represents normalized event/alert severity levels.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityRank returns an ordered numeric rank for comparisons and prioritization.
func SeverityRank(s Severity) int {
	switch strings.ToLower(string(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// EventCategory enumerates normalized telemetry categories.
type EventCategory string

const (
	CategoryProcess     EventCategory = "process"
	CategoryAuth        EventCategory = "auth"
	CategoryFile        EventCategory = "file"
	CategoryPersistence EventCategory = "persistence"
	CategoryService     EventCategory = "service"
	CategoryNetwork     EventCategory = "network"
	CategoryHealth      EventCategory = "health"
)

// ProcessInfo captures endpoint process metadata.
type ProcessInfo struct {
	PID        int    `json:"pid,omitempty"`
	PPID       int    `json:"ppid,omitempty"`
	Name       string `json:"name,omitempty"`
	Executable string `json:"executable,omitempty"`
	Cmdline    string `json:"cmdline,omitempty"`
	User       string `json:"user,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

// FileInfo captures file integrity monitoring attributes.
type FileInfo struct {
	Path       string `json:"path,omitempty"`
	Action     string `json:"action,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	PrevSHA256 string `json:"prev_sha256,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Mode       string `json:"mode,omitempty"`
}

// AuthInfo captures authentication event attributes.
type AuthInfo struct {
	User      string `json:"user,omitempty"`
	Method    string `json:"method,omitempty"`
	Outcome   string `json:"outcome,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
	Service   string `json:"service,omitempty"`
	RawReason string `json:"raw_reason,omitempty"`
}

// NetworkInfo captures passive flow, DNS, and TLS SNI metadata.
type NetworkInfo struct {
	Protocol string `json:"protocol,omitempty"`
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	DNSQuery string `json:"dns_query,omitempty"`
	TLSSNI   string `json:"tls_sni,omitempty"`
	State    string `json:"state,omitempty"`
	Bytes    uint64 `json:"bytes,omitempty"`
}

// Event represents a canonical normalized security telemetry event.
type Event struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	AgentID    string            `json:"agent_id"`
	Host       string            `json:"host"`
	OS         string            `json:"os,omitempty"`
	Category   EventCategory     `json:"category"`
	Action     string            `json:"action"`
	Severity   Severity          `json:"severity"`
	OccurredAt time.Time         `json:"occurred_at"`
	IngestedAt time.Time         `json:"ingested_at"`
	Summary    string            `json:"summary"`
	Process    *ProcessInfo      `json:"process,omitempty"`
	File       *FileInfo         `json:"file,omitempty"`
	Auth       *AuthInfo         `json:"auth,omitempty"`
	Network    *NetworkInfo      `json:"network,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// LookupField extracts a normalized string value from dotted event paths.
func (e Event) LookupField(field string) (string, bool) {
	switch field {
	case "id":
		return e.ID, e.ID != ""
	case "tenant_id":
		return e.TenantID, e.TenantID != ""
	case "agent_id":
		return e.AgentID, e.AgentID != ""
	case "host":
		return e.Host, e.Host != ""
	case "os":
		return e.OS, e.OS != ""
	case "category":
		return string(e.Category), e.Category != ""
	case "action":
		return e.Action, e.Action != ""
	case "severity":
		return string(e.Severity), e.Severity != ""
	case "summary":
		return e.Summary, e.Summary != ""
	case "process.pid":
		if e.Process == nil {
			return "", false
		}
		return fmt.Sprintf("%d", e.Process.PID), true
	case "process.ppid":
		if e.Process == nil {
			return "", false
		}
		return fmt.Sprintf("%d", e.Process.PPID), true
	case "process.name":
		if e.Process == nil {
			return "", false
		}
		return e.Process.Name, e.Process.Name != ""
	case "process.executable":
		if e.Process == nil {
			return "", false
		}
		return e.Process.Executable, e.Process.Executable != ""
	case "process.cmdline":
		if e.Process == nil {
			return "", false
		}
		return e.Process.Cmdline, e.Process.Cmdline != ""
	case "process.user":
		if e.Process == nil {
			return "", false
		}
		return e.Process.User, e.Process.User != ""
	case "process.sha256":
		if e.Process == nil {
			return "", false
		}
		return e.Process.SHA256, e.Process.SHA256 != ""
	case "file.path":
		if e.File == nil {
			return "", false
		}
		return e.File.Path, e.File.Path != ""
	case "file.action":
		if e.File == nil {
			return "", false
		}
		return e.File.Action, e.File.Action != ""
	case "file.sha256":
		if e.File == nil {
			return "", false
		}
		return e.File.SHA256, e.File.SHA256 != ""
	case "auth.user":
		if e.Auth == nil {
			return "", false
		}
		return e.Auth.User, e.Auth.User != ""
	case "auth.method":
		if e.Auth == nil {
			return "", false
		}
		return e.Auth.Method, e.Auth.Method != ""
	case "auth.outcome":
		if e.Auth == nil {
			return "", false
		}
		return e.Auth.Outcome, e.Auth.Outcome != ""
	case "auth.source_ip":
		if e.Auth == nil {
			return "", false
		}
		return e.Auth.SourceIP, e.Auth.SourceIP != ""
	case "auth.service":
		if e.Auth == nil {
			return "", false
		}
		return e.Auth.Service, e.Auth.Service != ""
	case "network.protocol":
		if e.Network == nil {
			return "", false
		}
		return e.Network.Protocol, e.Network.Protocol != ""
	case "network.src_ip":
		if e.Network == nil {
			return "", false
		}
		return e.Network.SrcIP, e.Network.SrcIP != ""
	case "network.src_port":
		if e.Network == nil {
			return "", false
		}
		return fmt.Sprintf("%d", e.Network.SrcPort), e.Network.SrcPort > 0
	case "network.dst_ip":
		if e.Network == nil {
			return "", false
		}
		return e.Network.DstIP, e.Network.DstIP != ""
	case "network.dst_port":
		if e.Network == nil {
			return "", false
		}
		return fmt.Sprintf("%d", e.Network.DstPort), e.Network.DstPort > 0
	case "network.dns_query":
		if e.Network == nil {
			return "", false
		}
		return e.Network.DNSQuery, e.Network.DNSQuery != ""
	case "network.tls_sni":
		if e.Network == nil {
			return "", false
		}
		return e.Network.TLSSNI, e.Network.TLSSNI != ""
	default:
		if strings.HasPrefix(field, "metadata.") && e.Metadata != nil {
			k := strings.TrimPrefix(field, "metadata.")
			v, ok := e.Metadata[k]
			return v, ok && v != ""
		}
		return "", false
	}
}

// Validate checks minimal required integrity invariants for an event.
func (e *Event) Validate() error {
	if strings.TrimSpace(e.AgentID) == "" {
		return fmt.Errorf("event missing agent_id")
	}
	if strings.TrimSpace(e.Category.String()) == "" {
		return fmt.Errorf("event missing category")
	}
	if strings.TrimSpace(e.Action) == "" {
		return fmt.Errorf("event missing action")
	}
	if e.TenantID == "" {
		e.TenantID = "default"
	}
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	if e.IngestedAt.IsZero() {
		e.IngestedAt = time.Now().UTC()
	}
	return nil
}

// String returns the string form of EventCategory.
func (c EventCategory) String() string {
	return string(c)
}

// Agent represents a registered endpoint running sentinelmesh-agent.
type Agent struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	Hostname       string            `json:"hostname"`
	OS             string            `json:"os"`
	Arch           string            `json:"arch"`
	Version        string            `json:"version"`
	IPAddress      string            `json:"ip_address"`
	Status         string            `json:"status"` // online, degraded, offline, quarantined
	CPUPercent     float64           `json:"cpu_percent"`
	MemoryUsedMB   float64           `json:"memory_used_mb"`
	MemoryTotalMB  float64           `json:"memory_total_mb"`
	AgentRSSMB     float64           `json:"agent_rss_mb"`
	Quarantined    bool              `json:"quarantined"`
	PolicyVersion  int               `json:"policy_version"`
	Labels         map[string]string `json:"labels,omitempty"`
	HMACSecretHash string            `json:"-"`
	HMACSecret     string            `json:"-"`
	RegisteredAt   time.Time         `json:"registered_at"`
	LastHeartbeat  time.Time         `json:"last_heartbeat"`
}

// AlertStatus represents alert workflow lifecycle states.
type AlertStatus string

const (
	AlertOpen          AlertStatus = "open"
	AlertAcknowledged  AlertStatus = "acknowledged"
	AlertFalsePositive AlertStatus = "false_positive"
	AlertSuppressed    AlertStatus = "suppressed"
	AlertResolved      AlertStatus = "resolved"
)

// Alert is emitted by a detection rule, correlation window, IOC hit, or EWMA baseline anomaly.
type Alert struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	RuleID         string            `json:"rule_id"`
	RuleName       string            `json:"rule_name"`
	RuleVersion    int               `json:"rule_version"`
	AgentID        string            `json:"agent_id"`
	Host           string            `json:"host"`
	Severity       Severity          `json:"severity"`
	Status         AlertStatus       `json:"status"`
	Priority       int               `json:"priority"`
	MITRE          []string          `json:"mitre,omitempty"`
	Explanation    string            `json:"explanation"`
	DedupKey       string            `json:"dedup_key"`
	HitCount       int               `json:"hit_count"`
	EventIDs       []string          `json:"event_ids"`
	Evidence       map[string]string `json:"evidence,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	LastSeenAt     time.Time         `json:"last_seen_at"`
	AcknowledgedBy string            `json:"acknowledged_by,omitempty"`
	IncidentID     string            `json:"incident_id,omitempty"`
}

// IncidentStatus defines valid administrative incident lifecycle states.
type IncidentStatus string

const (
	IncidentOpen          IncidentStatus = "open"
	IncidentInvestigating IncidentStatus = "investigating"
	IncidentContained     IncidentStatus = "contained"
	IncidentResolved      IncidentStatus = "resolved"
	IncidentClosed        IncidentStatus = "closed"
)

// ValidIncidentTransition enforces controlled incident state transitions.
func ValidIncidentTransition(from, to IncidentStatus) bool {
	if from == to {
		return true
	}
	allowed := map[IncidentStatus][]IncidentStatus{
		IncidentOpen:          {IncidentInvestigating, IncidentContained, IncidentResolved, IncidentClosed},
		IncidentInvestigating: {IncidentContained, IncidentResolved, IncidentClosed, IncidentOpen},
		IncidentContained:     {IncidentResolved, IncidentInvestigating, IncidentClosed},
		IncidentResolved:      {IncidentClosed, IncidentInvestigating},
		IncidentClosed:        {IncidentInvestigating},
	}
	for _, next := range allowed[from] {
		if next == to {
			return true
		}
	}
	return false
}

// Incident groups correlated alerts for investigation and response.
type Incident struct {
	ID              string         `json:"id"`
	TenantID        string         `json:"tenant_id"`
	Title           string         `json:"title"`
	Summary         string         `json:"summary"`
	Severity        Severity       `json:"severity"`
	Status          IncidentStatus `json:"status"`
	Assignee        string         `json:"assignee,omitempty"`
	Recommendations []string       `json:"recommendations,omitempty"`
	AlertIDs        []string       `json:"alert_ids,omitempty"`
	ApprovedBy      string         `json:"approved_by,omitempty"`
	CreatedBy       string         `json:"created_by"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// IncidentNote captures analyst notes and evidence links attached to an incident.
type IncidentNote struct {
	ID          string    `json:"id"`
	IncidentID  string    `json:"incident_id"`
	TenantID    string    `json:"tenant_id"`
	Author      string    `json:"author"`
	Note        string    `json:"note"`
	EvidenceRef string    `json:"evidence_ref,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// IOCType defines supported threat intelligence indicator categories.
type IOCType string

const (
	IOCIP     IOCType = "ip"
	IOCCIDR   IOCType = "cidr"
	IOCDomain IOCType = "domain"
	IOCSHA256 IOCType = "sha256"
	IOCURL    IOCType = "url"
)

// ThreatIndicator stores a threat intelligence IOC with expiration and confidence.
type ThreatIndicator struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Type        IOCType   `json:"type"`
	Value       string    `json:"value"`
	Confidence  int       `json:"confidence"`
	Severity    Severity  `json:"severity"`
	Source      string    `json:"source"`
	Description string    `json:"description,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// User represents an operator account with RBAC role and tenant scope.
type User struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	Role         Role       `json:"role"`
	PasswordHash string     `json:"-"`
	Disabled     bool       `json:"disabled"`
	FailedLogins int        `json:"-"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// AuditEntry records immutable security and administrative actions.
type AuditEntry struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Actor     string    `json:"actor"`
	ActorRole string    `json:"actor_role"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Outcome   string    `json:"outcome"`
	Details   string    `json:"details,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// EnrollmentToken authorizes new endpoint agent onboarding.
type EnrollmentToken struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	TokenHash string    `json:"-"`
	Label     string    `json:"label"`
	CreatedBy string    `json:"created_by"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	UsedCount int       `json:"used_count"`
	CreatedAt time.Time `json:"created_at"`
}
