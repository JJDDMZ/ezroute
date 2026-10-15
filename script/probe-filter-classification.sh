#!/usr/bin/env bash
# One offline run: typecheck public APIs and replay information-loss counterexamples.
set -euo pipefail
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/private/tmp}/ez-switch-filter-classification.XXXXXX")"
run_probe() {
    printf 'Offline classification probe\nLog: %s/output.log\n' "$OUTPUT_DIR"
    printf '%s\n' 'No filter activation, network requests or live configuration access.'
    xcrun swiftc -typecheck -module-cache-path "$OUTPUT_DIR/module-cache" \
        routing/prototypes/filter-classification/FilterAPISurface.swift || return "$?"
    printf '%s\n' 'Declared API typecheck: PASS'
    /usr/bin/python3 routing/prototypes/filter-classification/probe.py "$@" || return "$?"
    printf '%s\n' 'Counterexamples reproduced; this is not runtime filtering acceptance.'
}
if run_probe "$@" > "$OUTPUT_DIR/output.log" 2>&1; then
    STATUS=0
else
    STATUS=$?
fi
cat "$OUTPUT_DIR/output.log"
exit "$STATUS"
