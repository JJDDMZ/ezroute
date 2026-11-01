#!/bin/zsh
set -eu
ROOT="${0:A:h:h}"
exec /usr/bin/python3 "$ROOT/routing/tools/test_campus_usb_unplug.py" "$@"
