# ADR 001 — Core Stack, Storage Engine, and Security Model

- **Status:** Accepted
- **Date:** 2026-11-18
- **Project:** SentinelMesh

## Context

SentinelMesh requires a central management server, low-footprint cross-platform endpoint agents (Linux and Windows), fast rule correlation, binary PCAP dissection, and zero-dependency self-hosted deployment.

## Decision

1. **Go 1.27 (`modernc.org/sqlite`, `golang.org/x/crypto`, `gopkg.in/yaml.v3`, `github.com/google/uuid`)**:
   - Single static binary distribution for Linux and Windows agents and servers without CGO toolchain requirements.
   - Standard-library `crypto/*` and `golang.org/x/crypto/argon2` avoid custom cryptography.
   - Native `go test -race` and `go test -fuzz` support for concurrency and parser safety.
2. **Event Storage**:
   - SQLite in WAL mode with `synchronous=NORMAL`, foreign keys enabled, multi-tenant `tenant_id` partitioning, and batched transactions inside `internal/pipeline`.
3. **Detection Model**:
   - Deterministic YAML rule engine + sliding-window correlation + explicit statistical EWMA Z-score anomaly baseline (`anomaly.go`). No fabricated "AI" claims.
4. **Agent Transport Security**:
   - Enrollment token exchange issues scoped per-agent HMAC secrets (`hmac_secret`) bound to `agent_id` + `tenant_id`. Every ingestion batch carries `X-Sentinel-Agent-ID`, `X-Sentinel-Timestamp`, `X-Sentinel-Nonce`, and `X-Sentinel-Signature` over request body + headers, with optional mTLS (`--tls-client-ca`).

## Consequences

- Easy deployment as a single binary or Docker container.
- All database access passes through parameterized SQL and tenant guards.
- Statistical anomaly alerts clearly expose baseline mean, standard deviation, and Z-score in alert evidence.
