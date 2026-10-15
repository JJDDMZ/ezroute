#!/usr/bin/env bash
# Unified offline checks, explicit Chinese guided checks, and strict readiness.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec /usr/bin/python3 "$ROOT_DIR/routing/tools/verify_routing_suite.py" "$@"
