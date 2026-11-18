#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin
go build -trimpath -o bin/sentinelmesh-server ./cmd/sentinelmesh-server
go build -trimpath -o bin/sentinelmesh-agent ./cmd/sentinelmesh-agent
go build -trimpath -o bin/sentinelmesh ./cmd/sentinelmesh
echo "Built binaries in ./bin/"
