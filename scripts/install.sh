#!/usr/bin/env bash
set -euo pipefail
command -v go >/dev/null 2>&1 || { echo "Error: Go 1.24+ is required (not found in PATH)." >&2; exit 1; }
cd "$(dirname "$0")/.."
go mod download
./scripts/build.sh
echo "SentinelMesh installed into $(pwd)/bin"
