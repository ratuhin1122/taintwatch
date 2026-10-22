#!/bin/sh
# Build locally; publishing a GitHub release is a separate human action.
set -eu
version=0.1.0
mkdir -p build/release
for os in linux darwin; do
    for arch in amd64 arm64; do
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-X main.version=$version" -o "build/release/taintwatch-$os-$arch" ./cmd/taintwatch
    done
done
cd build/release
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum taintwatch-* > checksums.txt
else
    shasum -a 256 taintwatch-* > checksums.txt
fi
