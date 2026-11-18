# SentinelMesh STRIDE Threat Model

## Scope & Assets

| Asset | Sensitivity | Owner |
| :--- | :--- | :--- |
| Endpoint Event Telemetry (processes, cmdlines, auth logs, DNS) | High (may contain PII/CLI args) | Tenant / Server |
| Agent Credentials (`hmac_secret`, mTLS certs) | Critical | Agent / Server |
| User Credentials (`argon2id` hashes, JWT signing key) | Critical | Server |
| Detection Rules & Update Manifests | High (integrity critical) | Admin / Server |
| Threat Intel IOCs & Incident Evidence | High | Analyst / Responder |

## Trust Boundaries

1. **Untrusted Network -> Server HTTP/TLS API**: Agent ingestion, operator UI, and REST API cross host network boundaries.
2. **Endpoint Host -> Agent Collector**: Compromised endpoint could attempt to spoof another agent's `agent_id` or flood the collector queue.
3. **Untrusted PCAP / Log Input -> Parsers**: Malformed packets or log lines could trigger panics, integer overflows, or memory exhaustion.
4. **Server -> Sandboxed Plugin Subprocess**: Plugins could attempt credential harvesting via environment variables or runaway execution.

## STRIDE Analysis & Mitigations

| Threat | Category | Attack Vector | Mitigation | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| Agent Impersonation | Spoofing | Replaying or forging `agent_id` in telemetry | Per-agent unique `hmac_secret`, HMAC-SHA256 over `timestamp + nonce + method + path + sha256(body)`, ±5m timestamp window + replay nonce cache, optional mTLS | Compromised host with agent key can spoof its own host events |
| Telemetry Poisoning / Log Forging | Tampering | Injecting raw HTML/ANSI or malicious secrets into process cmdline | Output escaping in Web UI (`textContent`/escaped helpers), CLI flag secret redaction (`--password`, `Bearer `, `gho_`), strict field length limits | Legitimate noisy commands may need custom redaction patterns |
| Brute-Force / Token Theft | Information Disclosure & Elevation | Credential stuffing `/api/v1/auth/login` or stealing JWT | Argon2id (`time=2, mem=64MB`), per-IP token bucket rate limiter, 5-failure account lockout window, strict RBAC (`admin`/`responder`/`analyst`/`viewer`) | Weak operator password if policy disabled |
| Malformed PCAP Crash / OOM | Denial of Service | Crafted PCAP with huge `incl_len` or truncated headers | Hard per-packet snaplen cap (64 KiB), max file cap, bounds-checked slice reads, Go fuzz testing (`FuzzParsePCAP`) | Large legitimate multi-GB PCAPs require CLI streaming split |
| Telemetry Flood OOM | Denial of Service | Compromised/buggy agent flooding `/api/v1/ingest` | Bounded channel queue (`QueueCapacity`), HTTP `429 Retry-After` backpressure, max batch/body size (2 MiB) | Temporary telemetry delay during sustained DDoS |
| Rogue Update Binary | Elevation of Privilege | MITM or compromised mirror serving malicious agent update | `Ed25519` detached signature verification over SHA-256 package hash against pinned public key before applying updates | Compromise of release signing private key |
| Plugin Breakout / Env Leak | Information Disclosure / DoS | Plugin reading server `SENTINELMESH_JWT_SECRET` or hanging | Subprocess started with minimal scrubbed `env` (`PATH`, `SENTINEL_PLUGIN_ID`), context timeout, capped stdout/stderr buffers | Process runs as server OS user unless container/seccomp wrapped |
