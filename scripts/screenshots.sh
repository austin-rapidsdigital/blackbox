#!/bin/sh
# Regenerates docs/screenshots/*.png from the synthetic sample.
# Needs Chromium's headless_shell; set CHROME to its path if it is not
# found automatically.
set -eu
cd "$(dirname "$0")/.."
CHROME="${CHROME:-$(ls /opt/pw-browsers/chromium_headless_shell-*/chrome-linux/headless_shell 2>/dev/null | head -1)}"
[ -x "$CHROME" ] || { echo "set CHROME to a Chromium headless_shell binary" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
go run ./cmd/blackbox report --xml testdata/sample-events.xml --out "$tmp/r" --config /nonexistent >/dev/null
for v in overview:overview failed-logons:r13 usb:removable_media privileged:privileged health:health; do
	name=${v%%:*}
	view=${v#*:}
	"$CHROME" --no-sandbox --disable-gpu --hide-scrollbars --window-size=2560,1300 \
		--screenshot="docs/screenshots/$name.png" "file://$tmp/r/report.html#$view" >/dev/null 2>&1
	echo "docs/screenshots/$name.png"
done
