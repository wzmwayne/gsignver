#!/bin/sh
# 交叉编译多架构二进制（面向容器分发）。
set -eu
VERSION="${VERSION:-1.0.0}"
OUT="${OUT:-dist}"
mkdir -p "$OUT"

build() {
  os=$1; arch=$2; arm=$3; name=$4
  echo "==> $os/$arch$arm"
  GOOS=$os GOARCH=$arch GOARM=$arm CGO_ENABLED=0 go build \
    -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/gsignver-$name" ./cmd/gsignver
  GOOS=$os GOARCH=$arch GOARM=$arm CGO_ENABLED=0 go build \
    -trimpath -ldflags "-s -w" -o "$OUT/gsigtest-$name" ./cmd/gsigtest
}

build linux amd64 "" amd64
build linux arm64 "" arm64
build linux arm 7 armv7
build linux arm 6 armv6

ls -la "$OUT"
