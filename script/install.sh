#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./script/build_and_run.sh --build-only
/usr/bin/python3 script/install_app.py --source "$PWD/dist/EZ Route.app"
