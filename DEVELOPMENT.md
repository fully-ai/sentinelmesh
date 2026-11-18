# Development Guide

## Prerequisites
- Go 1.24+ (tested on Go 1.27.4)

## Commands
```bash
go mod download
go test -race -cover ./...
go test -fuzz=FuzzParsePCAP -fuzztime=10s ./internal/netmon
go test -fuzz=FuzzParseRuleYAML -fuzztime=10s ./internal/detection
./scripts/build.sh
```

## Troubleshooting
- **HTTP 429 on `/api/v1/ingest`**: Server bounded ingestion queue is saturated; verify agent disk spool is draining or tune `-queue-cap`.
- **403 on `/api/v1/agents/{id}/quarantine`**: Disruptive actions are disabled by default; start server with `-allow-disruptive` only after verifying operational controls.
