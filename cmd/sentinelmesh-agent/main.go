package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/agent"
)

type persistedCreds struct {
	AgentID    string `json:"agent_id"`
	TenantID   string `json:"tenant_id"`
	HMACSecret string `json:"hmac_secret"`
}

func main() {
	serverURL := flag.String("server", "http://127.0.0.1:8440", "SentinelMesh server base URL")
	enrollToken := flag.String("enroll-token", os.Getenv("SENTINELMESH_ENROLL_TOKEN"), "One-time or multi-use enrollment token")
	credsPath := flag.String("creds", "data/agent-creds.json", "Path to persisted agent credentials")
	spoolPath := flag.String("spool", "data/agent-spool.json", "Path to offline event spool file")
	fimList := flag.String("fim-paths", "/etc/passwd,/etc/sudoers,/etc/ssh/sshd_config", "Comma-separated FIM watch paths")
	persistList := flag.String("persist-paths", "/etc/cron.d,/etc/systemd/system", "Comma-separated persistence watch paths")
	pollSec := flag.Int("interval", 15, "Collection poll interval in seconds")
	once := flag.Bool("once", false, "Collect and ship one telemetry cycle then exit")
	flag.Parse()

	cfg := agent.Config{
		ServerURL:    strings.TrimRight(*serverURL, "/"),
		EnrollToken:  *enrollToken,
		SpoolPath:    *spoolPath,
		FIMPaths:     splitNonEmpty(*fimList),
		PersistPaths: splitNonEmpty(*persistList),
		PollInterval: time.Duration(*pollSec) * time.Second,
	}

	if raw, err := os.ReadFile(*credsPath); err == nil {
		var pc persistedCreds
		if json.Unmarshal(raw, &pc) == nil && pc.AgentID != "" && pc.HMACSecret != "" {
			cfg.AgentID = pc.AgentID
			cfg.TenantID = pc.TenantID
			cfg.HMACSecret = pc.HMACSecret
		}
	}

	ag := agent.New(cfg)
	ctx := context.Background()

	if cfg.HMACSecret == "" {
		if cfg.EnrollToken == "" {
			log.Fatal("agent has no stored credentials; provide -enroll-token to register")
		}
		if err := ag.Register(ctx); err != nil {
			log.Fatalf("agent registration failed: %v", err)
		}
		aid, tid, sec := ag.Credentials()
		_ = os.MkdirAll(filepath.Dir(*credsPath), 0o700)
		credBytes, _ := json.MarshalIndent(persistedCreds{AgentID: aid, TenantID: tid, HMACSecret: sec}, "", "  ")
		if err := os.WriteFile(*credsPath, credBytes, 0o600); err != nil {
			log.Printf("[AGENT] warning: failed to save creds file: %v", err)
		} else {
			log.Printf("[AGENT] Enrolled agent_id=%s (credentials saved 0600 to %s)", aid, *credsPath)
		}
	}

	runCycle := func() {
		if err := ag.SendHeartbeat(ctx); err != nil {
			log.Printf("[AGENT] heartbeat error: %v", err)
		}
		evs := ag.CollectOnce(ctx)
		if err := ag.ShipEvents(ctx, evs); err != nil {
			log.Printf("[AGENT] ship error (spooled locally): %v", err)
		} else {
			log.Printf("[AGENT] shipped %d telemetry events", len(evs))
		}
	}

	runCycle()
	if *once {
		return
	}

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			runCycle()
		case sig := <-sigCh:
			log.Printf("[AGENT] Received %s, exiting cleanly", sig)
			return
		}
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
