# SentinelMesh Roadmap

## v0.1.x (Alpha)
- Core SIEM/EDR ingestion pipeline, correlation engine, PCAP dissector, IOC matching, RBAC, and embedded SOC dashboard.

## v0.2.x (Planned)
- PostgreSQL / ClickHouse pluggable event storage backend alongside SQLite WAL.
- Live AF_PACKET / eBPF ringbuffer optional Linux process/execve collector for sub-millisecond short-lived process capture.
- STIX 2.1 / TAXII feed polling client.

## v0.3.x (Planned)
- Multi-node HA server clustering and read replicas.
- Automated Ed25519 self-update staging rollout for fleet agents.
