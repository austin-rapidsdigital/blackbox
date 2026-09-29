#!/bin/sh
# Builds release binaries into dist/ with SHA-256 checksums.
# Pure Go, no cgo, no third-party modules: builds fully offline.
#   VERSION=1.0.0 scripts/build.sh
set -eu
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
FLAGS="-trimpath -buildvcs=false"
LDFLAGS="-s -w -buildid= -X main.version=${VERSION}"
rm -rf dist && mkdir -p dist
build() {
	echo "building $3"
	CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build $FLAGS -ldflags "$LDFLAGS" -o "dist/$3" ./cmd/blackbox
}
build windows amd64 blackbox.exe
build linux amd64 blackbox-linux-amd64
build linux arm64 blackbox-linux-arm64
(cd dist && sha256sum * > SHA256SUMS)
cat dist/SHA256SUMS
