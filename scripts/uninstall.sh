#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf bin/
echo "Removed compiled binaries in ./bin (user data/ databases preserved)."
