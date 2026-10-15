#!/usr/bin/env bash
# Offline source review only: no listeners, DNS, controller access or activation.
set -euo pipefail
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/private/tmp}/ez-switch-executor-separation.XXXXXX")"
if /usr/bin/python3 routing/prototypes/executor-separation/probe.py "$@" > "$OUTPUT_DIR/output.log" 2>&1; then
    STATUS=0
else
    STATUS=$?
fi
printf 'Offline executor source review; log: %s/output.log\n' "$OUTPUT_DIR"
cat "$OUTPUT_DIR/output.log"
exit "$STATUS"
