# Changelog

## v0.1.0-alpha.1 (2026-11-18)

- Initial public Alpha release under Apache-2.0.
- Implemented `sentinelmesh-server` (REST API, RBAC, Argon2id, HMAC+nonce agent auth, mTLS support, SQLite WAL storage, retention, audit logs, sandboxed plugins).
- Implemented `sentinelmesh-agent` (Linux `/proc`/FIM/auth/persistence/net collectors, Windows build-tagged collectors, disk spooling).
- Implemented YAML rule & correlation engine, EWMA Z-score baseline tracker, pure-Go PCAP dissector, IOC matcher, operator CLI, and embedded SOC dashboard.
