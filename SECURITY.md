# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :---: |
| `0.1.x` (latest Alpha) | Yes |

## Reporting a Vulnerability

Please **do not** open public GitHub issues for security vulnerabilities.

Instead:
1. Open a private GitHub Security Advisory at `https://github.com/fully-ai/sentinelmesh/security/advisories/new`.
2. Include steps to reproduce, affected version/commit, component (`server`, `agent`, `netmon`, `api`, `web`), and potential impact.
3. Expect an initial acknowledgment within 48 hours and coordinated disclosure once a fix and regression test are verified.

## Security Boundaries & Safe Defaults

- SentinelMesh is strictly a defensive monitoring and response coordination platform.
- Passive network monitoring and endpoint telemetry require explicit enrollment and authorization.
- Disruptive response actions (e.g., host containment/quarantine flags) are disabled by default (`SENTINELMESH_ALLOW_DISRUPTIVE=false`) and require explicit `admin` or `responder` RBAC authorization plus audit logging.
- Sensitive command-line arguments (`--password`, `Bearer`, API tokens) are redacted prior to ingestion persistence.
