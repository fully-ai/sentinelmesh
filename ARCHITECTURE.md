# SentinelMesh Architecture

SentinelMesh is a modular, defensive cybersecurity, SIEM, EDR, and XDR ecosystem written in Go with an embedded real-time SOC web dashboard.

## System Topology

```
+-----------------------------+         HTTPS / optional mTLS         +------------------------------------+
| Endpoint Hosts (Linux/Win)  |     + HMAC-SHA256 Signed Batch      |      SentinelMesh Server           |
|                             | ----------------------------------> |                                    |
|  sentinelmesh-agent         |                                     |  +------------------------------+  |
|   - Process /proc collector | <---------------------------------- |  | Auth / RBAC / Rate Limiter   |  |
|   - FIM SHA-256 watcher     |   Signed Policy + Ed25519 Manifest  |  +--------------+---------------+  |
|   - Auth / Service / Cron   |                                     |                 |                  |
|   - Passive Net / DNS       |                                     |  +--------------v---------------+  |
|   - Disk Spool Buffer       |                                     |  | Bounded Ingestion Pipeline   |  |
+-----------------------------+                                     |  | (Redaction + Backpressure)   |  |
                                                                    |  +--+------------------------+--+  |
                                                                    |     |                        |     |
+-----------------------------+                                     |  +--v-----------+     +------v--+  |
|  SOC Operator / Admin       |         REST API + Embedded UI      |  | Detection &  |     | Threat  |  |
|   - Web SOC Dashboard       | <---------------------------------> |  | Correlation  | <-> | Intel   |  |
|   - sentinelmesh CLI        |         JWT + RBAC + Audit          |  | (YAML/EWMA)  |     | IOCs    |  |
+-----------------------------+                                     |  +------+-------+     +---------+  |
                                                                    |         |                          |
+-----------------------------+                                     |  +------v-----------------------+  |
|  Sandboxed Plugins (stdio)  | <-------- Subprocess JSON --------> |  | SQLite WAL Store + Retention |  |
+-----------------------------+                                     |  +------------------------------+  |
```

## Subsystems

1. **`internal/domain`**: Canonical schemas for `Event`, `Alert`, `Incident`, `Agent`, `Rule`, `IOC`, `NetworkFlow`, `AuditLog`, `User`, `Tenant`.
2. **`internal/crypto`**: Argon2id password hashing, HMAC-SHA256 payload/token authentication with anti-replay nonce cache, Ed25519 manifest/update signature verification, TLS/mTLS helpers.
3. **`internal/storage`**: Multi-tenant SQLite (`modernc.org/sqlite`) with WAL mode, migrations, indexed query engine, configurable retention pruning, and integrity checks.
4. **`internal/pipeline`**: Bounded worker pool providing explicit backpressure (`ErrQueueFull` -> HTTP `429`), CLI flag/token secret redaction, Threat Intel enrichment, and asynchronous batched writes.
5. **`internal/detection`**: Single-event rule matching, temporal sliding-window correlation, sequence correlation, deduplication/suppression, false-positive suppression, rule versioning, MITRE ATT&CK mapping, and EWMA Z-score host rate anomaly scoring.
6. **`internal/netmon`**: Pure-Go libpcap parser (`Ethernet`, `IPv4`, `IPv6`, `TCP`, `UDP`, `ICMP`, DNS QNAME dissector, TLS ClientHello SNI extractor) and network anomaly checks (high DNS entropy/length, high-port fan-out).
7. **`internal/threatintel`**: IOC registry (`ip`, `cidr`, `domain`, `sha256`, `url`) with expiration, confidence scores, O(1) lookup indexes, CSV/JSON import/export.
8. **`internal/plugin`**: Sandboxed subprocess JSON protocol (`stdin`/`stdout`, stripped env, timeout, bounded output).
9. **`internal/agent`**: Modular OS collectors (`linux`, `windows`), offline disk spooling, signed config sync, and Ed25519 package verification.
10. **`internal/api`**: REST API (`/api/v1/*`), RBAC (`admin`, `responder`, `analyst`, `viewer`), per-IP token-bucket rate limiter, brute-force account lockout, audit trail, embedded SOC UI (`web/`).

## Design Decisions & Trade-offs

- **SQLite WAL vs Embedded/External TSDB**: Single-binary zero-external-dependency deployment guarantees low operational friction for self-hosted teams. Write throughput scales cleanly via batched WAL commits and strict composite indexes; bounded retention prevents unbounded growth.
- **No Unbounded Ingestion**: Ingestion returns explicit HTTP `429 Retry-After` under saturation while agents retain events in a bounded disk spool rather than risking OOM on the central server.
- **Disruptive Actions Disabled by Default**: Host isolation/process containment endpoints require both server-side explicit opt-in (`ALLOW_DISRUPTIVE_RESPONSE=true`) and `admin`/`responder` RBAC approval.
