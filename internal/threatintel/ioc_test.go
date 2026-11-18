package threatintel

import (
	"testing"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/domain"
)

func TestIOCMatchingCIDRExpirationAndCSV(t *testing.T) {
	now := time.Now().UTC()
	csvData := []byte("type,value,severity,confidence,source,description\n" +
		"ip,203.0.113.5,high,90,feed-a,C2 IP\n" +
		"cidr,198.51.100.0/24,critical,95,feed-b,Bad Range\n" +
		"domain,evil.example,high,85,feed-c,Malicious domain\n" +
		"sha256,deadbeef001122,critical,99,feed-d,Bad hash\n")

	list, err := ParseCSV(csvData, "default", now)
	if err != nil || len(list) != 4 {
		t.Fatalf("ParseCSV err=%v len=%d", err, len(list))
	}
	// Add expired indicator that must be ignored
	list = append(list, domain.ThreatIndicator{
		ID:        "exp-1",
		TenantID:  "default",
		Type:      domain.IOCIP,
		Value:     "192.0.2.99",
		ExpiresAt: now.Add(-time.Hour),
	})

	m := NewMatcher(list, now)
	matches := m.MatchEvent(domain.Event{
		Auth:    &domain.AuthInfo{SourceIP: "198.51.100.42"},
		Network: &domain.NetworkInfo{DstIP: "203.0.113.5", DNSQuery: "sub.evil.example."},
		Process: &domain.ProcessInfo{SHA256: "DEADBEEF001122"},
	})
	if len(matches) != 4 {
		t.Fatalf("expected 4 IOC matches (cidr, ip, parent-domain, sha256), got %d (%+v)", len(matches), matches)
	}

	expMatches := m.MatchEvent(domain.Event{Auth: &domain.AuthInfo{SourceIP: "192.0.2.99"}})
	if len(expMatches) != 0 {
		t.Fatalf("expected expired IOC to be ignored, got %+v", expMatches)
	}

	if js, err := ExportJSON(list[:4]); err != nil || len(js) == 0 {
		t.Fatalf("ExportJSON failed: %v", err)
	}
}
