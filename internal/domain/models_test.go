package domain

import "testing"

func TestRolesAndTransitions(t *testing.T) {
	if !ValidRole(RoleAdmin) || !ValidRole(RoleAnalyst) || !ValidRole(RoleResponder) || !ValidRole(RoleViewer) {
		t.Fatal("expected valid roles")
	}
	if ValidRole("superuser") {
		t.Fatal("unexpected unknown role valid")
	}
	if !CanPerform(RoleViewer, "read") || CanPerform(RoleViewer, "alert:ack") {
		t.Fatal("unexpected viewer permissions")
	}
	if !CanPerform(RoleAnalyst, "pcap:analyze") || CanPerform(RoleAnalyst, "quarantine") {
		t.Fatal("unexpected analyst permissions")
	}
	if !CanPerform(RoleResponder, "quarantine") || CanPerform(RoleResponder, "user:manage") {
		t.Fatal("unexpected responder permissions")
	}
	if !CanPerform(RoleAdmin, "user:manage") {
		t.Fatal("expected admin permissions")
	}

	if !ValidIncidentTransition(IncidentOpen, IncidentInvestigating) || ValidIncidentTransition(IncidentClosed, IncidentResolved) {
		t.Fatal("unexpected incident transition result")
	}
	if SeverityRank(SeverityCritical) <= SeverityRank(SeverityHigh) {
		t.Fatal("unexpected severity rank ordering")
	}
}

func TestEventLookupFieldAndValidation(t *testing.T) {
	ev := Event{
		AgentID:  "a1",
		Host:     "h1",
		Category: CategoryProcess,
		Action:   "started",
		Process:  &ProcessInfo{PID: 10, PPID: 1, Name: "sh", Executable: "/bin/sh", Cmdline: "sh -c id", User: "0", SHA256: "abc"},
		File:     &FileInfo{Path: "/etc/passwd", Action: "modified", SHA256: "def"},
		Auth:     &AuthInfo{User: "bob", Method: "ssh", Outcome: "failure", SourceIP: "1.2.3.4", Service: "sshd"},
		Network:  &NetworkInfo{Protocol: "DNS", SrcIP: "10.0.0.2", SrcPort: 5555, DstIP: "8.8.8.8", DstPort: 53, DNSQuery: "ex.com", TLSSNI: "ex.com"},
		Metadata: map[string]string{"dns_anomaly": "true"},
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	checks := map[string]string{
		"host":                 "h1",
		"process.name":         "sh",
		"process.sha256":       "abc",
		"file.path":            "/etc/passwd",
		"auth.source_ip":       "1.2.3.4",
		"network.dns_query":    "ex.com",
		"network.dst_port":     "53",
		"metadata.dns_anomaly": "true",
	}
	for f, want := range checks {
		got, ok := ev.LookupField(f)
		if !ok || got != want {
			t.Fatalf("LookupField(%s) = (%q, %v), want %q", f, got, ok, want)
		}
	}
}
