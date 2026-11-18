package threatintel

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/google/uuid"
)

// Match represents a hit against an active ThreatIndicator.
type Match struct {
	Indicator domain.ThreatIndicator `json:"indicator"`
	Field     string                 `json:"field"`
	Value     string                 `json:"value"`
}

// Matcher provides fast concurrency-safe IOC lookups over active indicators.
type Matcher struct {
	mu    sync.RWMutex
	exact map[string]map[string]domain.ThreatIndicator // type -> lower(value) -> ioc
	cidrs []cidrEntry
	all   []domain.ThreatIndicator
}

type cidrEntry struct {
	prefix netip.Prefix
	ioc    domain.ThreatIndicator
}

// NewMatcher builds an indexed matcher from a list of indicators, skipping expired ones.
func NewMatcher(indicators []domain.ThreatIndicator, now time.Time) *Matcher {
	m := &Matcher{
		exact: make(map[string]map[string]domain.ThreatIndicator),
	}
	m.Reload(indicators, now)
	return m
}

// Reload replaces the in-memory IOC index with non-expired entries.
func (m *Matcher) Reload(indicators []domain.ThreatIndicator, now time.Time) {
	exact := map[string]map[string]domain.ThreatIndicator{
		string(domain.IOCIP):     {},
		string(domain.IOCDomain): {},
		string(domain.IOCSHA256): {},
		string(domain.IOCURL):    {},
	}
	var cidrs []cidrEntry
	var active []domain.ThreatIndicator

	for _, ind := range indicators {
		if !ind.ExpiresAt.IsZero() && now.After(ind.ExpiresAt) {
			continue
		}
		val := strings.ToLower(strings.TrimSpace(ind.Value))
		if val == "" {
			continue
		}
		ind.Value = val
		active = append(active, ind)
		if ind.Type == domain.IOCCIDR {
			if p, err := netip.ParsePrefix(val); err == nil {
				cidrs = append(cidrs, cidrEntry{prefix: p, ioc: ind})
			}
			continue
		}
		if exact[string(ind.Type)] == nil {
			exact[string(ind.Type)] = map[string]domain.ThreatIndicator{}
		}
		exact[string(ind.Type)][val] = ind
	}

	m.mu.Lock()
	m.exact = exact
	m.cidrs = cidrs
	m.all = active
	m.mu.Unlock()
}

// MatchEvent checks IP, domain, file/process SHA-256, and URL attributes of ev.
func (m *Matcher) MatchEvent(ev domain.Event) []Match {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matches []Match
	checkIP := func(field, raw string) {
		if raw == "" {
			return
		}
		v := strings.ToLower(strings.TrimSpace(raw))
		if ioc, ok := m.exact[string(domain.IOCIP)][v]; ok {
			matches = append(matches, Match{Indicator: ioc, Field: field, Value: raw})
		}
		if addr, err := netip.ParseAddr(v); err == nil {
			for _, ce := range m.cidrs {
				if ce.prefix.Contains(addr) {
					matches = append(matches, Match{Indicator: ce.ioc, Field: field, Value: raw})
				}
			}
		}
	}
	checkDomain := func(field, raw string) {
		if raw == "" {
			return
		}
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if ioc, ok := m.exact[string(domain.IOCDomain)][d]; ok {
			matches = append(matches, Match{Indicator: ioc, Field: field, Value: raw})
			return
		}
		// Match parent domain labels (e.g., evil.example.com -> example.com)
		parts := strings.Split(d, ".")
		for i := 1; i < len(parts)-1; i++ {
			parent := strings.Join(parts[i:], ".")
			if ioc, ok := m.exact[string(domain.IOCDomain)][parent]; ok {
				matches = append(matches, Match{Indicator: ioc, Field: field, Value: raw})
				break
			}
		}
	}
	checkHash := func(field, raw string) {
		if raw == "" {
			return
		}
		if ioc, ok := m.exact[string(domain.IOCSHA256)][strings.ToLower(strings.TrimSpace(raw))]; ok {
			matches = append(matches, Match{Indicator: ioc, Field: field, Value: raw})
		}
	}

	if ev.Auth != nil {
		checkIP("auth.source_ip", ev.Auth.SourceIP)
	}
	if ev.Network != nil {
		checkIP("network.src_ip", ev.Network.SrcIP)
		checkIP("network.dst_ip", ev.Network.DstIP)
		checkDomain("network.dns_query", ev.Network.DNSQuery)
		checkDomain("network.tls_sni", ev.Network.TLSSNI)
	}
	if ev.Process != nil {
		checkHash("process.sha256", ev.Process.SHA256)
	}
	if ev.File != nil {
		checkHash("file.sha256", ev.File.SHA256)
	}
	return matches
}

// ParseCSV imports IOCs from CSV (`type,value,severity,confidence,source,description,ttl_hours`).
func ParseCSV(data []byte, tenantID string, now time.Time) ([]domain.ThreatIndicator, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse ioc csv: %w", err)
	}
	var out []domain.ThreatIndicator
	for idx, row := range rows {
		if len(row) < 2 {
			continue
		}
		if idx == 0 && strings.EqualFold(row[0], "type") {
			continue
		}
		sev := domain.SeverityMedium
		if len(row) > 2 && row[2] != "" {
			sev = domain.Severity(strings.ToLower(row[2]))
		}
		conf := 75
		if len(row) > 3 && row[3] != "" {
			_, _ = fmt.Sscanf(row[3], "%d", &conf)
		}
		src := "csv-import"
		if len(row) > 4 && row[4] != "" {
			src = row[4]
		}
		desc := ""
		if len(row) > 5 {
			desc = row[5]
		}
		out = append(out, domain.ThreatIndicator{
			ID:          uuid.NewString(),
			TenantID:    tenantID,
			Type:        domain.IOCType(strings.ToLower(row[0])),
			Value:       strings.ToLower(strings.TrimSpace(row[1])),
			Severity:    sev,
			Confidence:  conf,
			Source:      src,
			Description: desc,
			CreatedAt:   now,
			ExpiresAt:   now.Add(30 * 24 * time.Hour),
		})
	}
	return out, nil
}

// ExportJSON serializes active indicators to JSON.
func ExportJSON(indicators []domain.ThreatIndicator) ([]byte, error) {
	return json.MarshalIndent(indicators, "", "  ")
}
