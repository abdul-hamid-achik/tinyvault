#!/usr/bin/env bash
# Regenerates app/build/icon.icns and app/build/icon.png from app/build/icon.svg.
#
# macOS-only toolchain (qlmanage renders the SVG, sips resizes, iconutil packs).
# Run this after editing build/icon.svg; the outputs are committed so CI and
# other platforms never need the macOS tools.
#
# electron-builder picks both up automatically from buildResources: build.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=build/icon.svg
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

qlmanage -t -s 1024 -o "$WORK" "$SRC" >/dev/null 2>&1
PNG="$WORK/icon.svg.png"
if [ ! -f "$PNG" ]; then
  echo "error: qlmanage produced no PNG from $SRC" >&2
  exit 1
fi

mkdir -p "$WORK/icon.iconset"
sips -z 16    16    "$PNG" --out "$WORK/icon.iconset/icon_16x16.png"     >/dev/null
sips -z 32    32    "$PNG" --out "$WORK/icon.iconset/icon_16x16@2x.png"   >/dev/null
sips -z 32    32    "$PNG" --out "$WORK/icon.iconset/icon_32x32.png"      >/dev/null
sips -z 64    64    "$PNG" --out "$WORK/icon.iconset/icon_32x32@2x.png"   >/dev/null
sips -z 128   128   "$PNG" --out "$WORK/icon.iconset/icon_128x128.png"    >/dev/null
sips -z 256   256   "$PNG" --out "$WORK/icon.iconset/icon_128x128@2x.png" >/dev/null
sips -z 256   256   "$PNG" --out "$WORK/icon.iconset/icon_256x256.png"    >/dev/null
sips -z 512   512   "$PNG" --out "$WORK/icon.iconset/icon_256x256@2x.png" >/dev/null
sips -z 512   512   "$PNG" --out "$WORK/icon.iconset/icon_512x512.png"    >/dev/null
sips -z 1024  1024  "$PNG" --out "$WORK/icon.iconset/icon_512x512@2x.png" >/dev/null

iconutil -c icns "$WORK/icon.iconset" -o build/icon.icns
sips -z 512 512 "$PNG" --out build/icon.png >/dev/null

echo "wrote build/icon.icns ($(stat -f%z build/icon.icns) bytes) and build/icon.png"
