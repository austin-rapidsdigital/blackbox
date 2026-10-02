#!/bin/sh
# Builds release packages into dist/:
#   Blackbox-Setup-VERSION.exe           Windows: the one file to carry over (blackbox.exe marked windowed)
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
	if [ "$1" = windows ]; then
		exe=blackbox.exe
		# Program icon and version details (Properties > Details, Settings > Apps).
		syso="cmd/blackbox/rsrc_windows_$2.syso"
		go run ./scripts/winres -version "$VERSION" -arch "$2" -o "$syso"
	fi
	echo "building $name"
	CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$dir/$exe" ./cmd/blackbox
	if [ "$1" = windows ]; then
		rm -f "$syso"
		# Double-clicking it opens the setup window without a console;
		# setup installs blackbox.exe (console) and blackboxw.exe from it.
		go run ./scripts/winres -windowed "$dir/$exe" -o "dist/Blackbox-Setup-${VERSION}.exe"
	else
		cp packaging/linux/* "$dir/"
		cp LICENSE NOTICE "$dir/"
		chmod +x "$dir/blackbox" "$dir"/*.sh
		tar -C dist/stage -czf "dist/$name.tar.gz" "$name"
	fi
}
package windows amd64
package linux amd64
package linux arm64
rm -rf dist/stage
(cd dist && sha256sum -- *.exe *.tar.gz > SHA256SUMS)
cat dist/SHA256SUMS
