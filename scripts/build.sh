#!/bin/sh
# Builds release packages into dist/:
#   blackbox-VERSION-windows-amd64.zip   blackbox.exe + Install.cmd + Uninstall.cmd
#   blackbox-VERSION-linux-amd64.tar.gz  blackbox + install.sh + uninstall.sh
#   blackbox-VERSION-linux-arm64.tar.gz
#   SHA256SUMS
# Pure Go with no cgo and no third-party modules, so it builds fully offline.
#   VERSION=0.1.0 scripts/build.sh
set -eu
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"
LDFLAGS="-s -w -buildid= -X main.version=${VERSION}"
rm -rf dist && mkdir -p dist/stage

package() { # os arch
	name="blackbox-${VERSION}-$1-$2"
	dir="dist/stage/$name"
	mkdir -p "$dir"
	exe=blackbox
	[ "$1" = windows ] && exe=blackbox.exe
	echo "building $name"
	CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$dir/$exe" ./cmd/blackbox
	if [ "$1" = windows ]; then
		cp packaging/windows/* "$dir/"
		# Windows line endings for the batch files and readme.
		for f in "$dir"/*.cmd "$dir"/README.txt; do sed -i 's/$/\r/' "$f"; done
		(cd dist/stage && if command -v zip >/dev/null; then zip -qr "../$name.zip" "$name"; else python3 -m zipfile -c "../$name.zip" "$name"; fi)
	else
		cp packaging/linux/* "$dir/"
		chmod +x "$dir/blackbox" "$dir"/*.sh
		tar -C dist/stage -czf "dist/$name.tar.gz" "$name"
	fi
}
package windows amd64
package linux amd64
package linux arm64
rm -rf dist/stage
(cd dist && sha256sum -- *.zip *.tar.gz > SHA256SUMS)
cat dist/SHA256SUMS
