# SentinelMesh

**SentinelMesh** is a self-hosted, defensive Cybersecurity, SIEM, EDR, and XDR platform written in Go with an embedded SOC web operations console.

> **Maturity:** Alpha (`v0.1.0-alpha.1`) — Core server, Linux/Windows collectors, rule/correlation engine, PCAP analyzer, threat intel IOC matcher, sandboxed plugins, RBAC, and embedded SOC dashboard verified via unit, integration, `-race`, fuzz, and benchmark suites.

## Features

- **Central SIEM/XDR Management Server (`sentinelmesh-server`)**:
  - Bounded asynchronous ingestion pipeline with explicit HTTP `429 Retry-After` backpressure.
  - Multi-tenant SQLite WAL storage with composite indexes and automated retention pruning.
  - Argon2id authentication, per-IP rate limiting, failed-login account lockout, HMAC-SHA256 + nonce replay protection for endpoint agents, optional mTLS (`--tls-client-ca`), and immutable audit logging.
  - Secret redaction on ingested command lines (`Bearer`, `--password`, `--token`, `ghp_*`).
  - Sandboxed subprocess plugin runner (`stdin`/`stdout` JSON with scrubbed environment and timeouts).
- **Lightweight Endpoint Agent (`sentinelmesh-agent`)**:
  - Cross-platform collectors (`linux` via `/proc` & auth logs, `windows` via native build tags).
  - Process creation diffing, SHA-256 File Integrity Monitoring (FIM), persistence mechanism monitoring, auth log tailing, passive TCP socket snapshots, host CPU/RAM/agent-RSS metrics, and bounded disk spooling during outages.
- **Detection, Correlation & Statistical Anomaly Engine**:
  - Declarative YAML rules (`all`/`any`/`not`, `regex`, `cidr`, `in`, numeric comparisons).
  - Sliding time-window threshold correlation and multi-stage ordered sequence correlation with MITRE ATT&CK mapping and human-readable detection explanations.
  - Explainable per-(agent, category) EWMA Z-score rate anomaly detection.
- **Passive Network Telemetry & Threat Intelligence**:
  - Pure-Go Ethernet/IPv4/IPv6/TCP/UDP/ICMP/DNS/TLS-SNI `.pcap` dissector with DNS high-entropy/length tunneling detection.
  - Expiring IOC registry (`ip`, `cidr`, `domain`, `sha256`, `url`) with CSV/JSON import & export.
- **Embedded SOC Web Dashboard**:
  - Zero-CDN UI served directly by `sentinelmesh-server` at `/` with dark/light theme, Overview, Endpoints, Live Events, Alerts, Incident Timelines, YAML Rule Editor/Tester, PCAP Analyzer, Threat Intel, Audit Logs, Users/Roles, and Settings.

## Quick Start (Linux / macOS)

```bash
git clone https://github.com/fully-ai/sentinelmesh
cd sentinelmesh
./scripts/build.sh
./scripts/test.sh
./bin/sentinelmesh-server -addr 127.0.0.1:8440 -db data/sentinelmesh.db
```

On first boot, `sentinelmesh-server` creates an initial `admin` user and prints a randomly generated one-time password (unless `SENTINELMESH_ADMIN_PASSWORD` is supplied). Open `http://127.0.0.1:8440` and sign in.

## Enrolling an Endpoint Agent

1. Mint an enrollment token in the UI (**Endpoints -> Mint Enrollment Token**) or via `/api/v1/agents/tokens`.
2. Start the agent:
   ```bash
   ./bin/sentinelmesh-agent \
     -server http://127.0.0.1:8440 \
     -enroll-token <TOKEN> \
     -fim-paths /etc/passwd,/etc/sudoers
   ```

## CLI Usage

```bash
./bin/sentinelmesh rules defaults
./bin/sentinelmesh rules validate custom-rule.yml
./bin/sentinelmesh pcap analyze capture.pcap
./bin/sentinelmesh ioc parse-csv indicators.csv
./bin/sentinelmesh keygen
```

## Security Model & Known Limitations

- Disruptive response actions (quarantine policy toggle) are **disabled by default** and require `-allow-disruptive` (`SENTINELMESH_ALLOW_DISRUPTIVE=true`) plus `admin`/`responder` RBAC authorization.
- Windows runtime execution has not been verified directly on a Windows host in this environment (`GOOS=windows GOARCH=amd64` cross-compilation verified).
- See [ARCHITECTURE.md](ARCHITECTURE.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
