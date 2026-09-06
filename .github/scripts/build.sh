#!/usr/bin/env bash
set -euo pipefail
os=${1:?target OS}; arch=${2:?target architecture}
case "$os/$arch" in linux/amd64|linux/arm64|darwin/amd64|darwin/arm64) ;; *) exit 2;; esac
version=${VERSION:-dev}
if [[ ! "$version" =~ ^(dev(-[0-9a-f]+)?|v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$ ]]; then
  printf 'Invalid build version\n' >&2
  exit 2
fi
mkdir -p dist
CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
  -ldflags "-s -w -X main.version=$version" -o "dist/secscan-$os-$arch" ./cmd/secscan
