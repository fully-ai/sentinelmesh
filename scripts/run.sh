#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[ -x bin/sentinelmesh-server ] || ./scripts/build.sh
exec ./bin/sentinelmesh-server -addr "${SENTINELMESH_ADDR:-127.0.0.1:8440}" -db "${SENTINELMESH_DB:-data/sentinelmesh.db}"
