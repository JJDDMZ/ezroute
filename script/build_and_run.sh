#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export CLANG_MODULE_CACHE_PATH="$ROOT_DIR/.build/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$ROOT_DIR/.build/module-cache"

swift build --disable-sandbox --scratch-path .build --cache-path .build/cache
BUILD_DIR="$(swift build --disable-sandbox --scratch-path .build --cache-path .build/cache --show-bin-path)"
APP_BUNDLE="$ROOT_DIR/dist/EZ Route.app"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources/docs"
cp "$BUILD_DIR/EZSwitch" "$APP_BUNDLE/Contents/MacOS/EZSwitch"
cp docs/setup.md docs/hotspot-routing-preview.md docs/campus-profile.md docs/verification.md "$APP_BUNDLE/Contents/Resources/docs/"
# 旧包曾附带专注模式桥接研究，构建时移除该历史入口。
rm -f "$APP_BUNDLE/Contents/Resources/docs/research.md"
cp routing/clash-usb-wifi.js "$APP_BUNDLE/Contents/Resources/legacy-routing.js"
/usr/bin/python3 script/render_routing_bootstrap.py "$APP_BUNDLE/Contents/Resources/routing-bootstrap.js"
cp Resources/Info.plist "$APP_BUNDLE/Contents/Info.plist"
if [[ -f Resources/AppIcon.icns ]]; then
    cp Resources/AppIcon.icns "$APP_BUNDLE/Contents/Resources/"
fi
/usr/bin/codesign --force --sign - --identifier dev.ezswitch.app "$APP_BUNDLE"

case "$MODE" in
    --build-only) printf '%s\n' "$APP_BUNDLE" ;;
    run) /usr/bin/open "$APP_BUNDLE" ;;
    --verify)
        /usr/bin/open "$APP_BUNDLE"
        sleep 2
        pgrep -x EZSwitch >/dev/null
        printf '%s\n' "EZ Route is running."
        ;;
    --debug) lldb -- "$APP_BUNDLE/Contents/MacOS/EZSwitch" ;;
    --logs|--telemetry)
        /usr/bin/open "$APP_BUNDLE"
        /usr/bin/log stream --info --style compact --predicate 'process == "EZSwitch"'
        ;;
    *) printf '%s\n' 'usage: build_and_run.sh [run|--build-only|--verify|--debug|--logs|--telemetry]' >&2; exit 2 ;;
esac
