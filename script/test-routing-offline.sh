#!/usr/bin/env bash
# Compatibility entry: run all offline suites once into private logs.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT_DIR/script/verify-routing.sh" --offline "$@"
