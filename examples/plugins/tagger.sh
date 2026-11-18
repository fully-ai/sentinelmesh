#!/usr/bin/env bash
set -euo pipefail
# Example sandboxed SentinelMesh plugin: reads JSON alert on stdin, emits enrichment JSON on stdout.
payload="$(cat)"
if [ -z "$payload" ]; then
  echo '{"message":"empty payload","tags":["sentinelmesh"]}'
  exit 0
fi
echo '{"message":"enriched via sandboxed tagger","tags":["soc-triaged","plugin-verified"],"metadata":{"plugin_sandbox":"scrubbed-env"}}'
