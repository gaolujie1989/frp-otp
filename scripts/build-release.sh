#!/bin/sh
set -eu

version="${1:-$(cat VERSION)}"
if ! printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "expected version vMAJOR.MINOR.PATCH" >&2
  exit 2
fi
out="${2:-release/$version}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
if [ -n "$(ls -A "$out")" ]; then
  echo "output directory must be empty: $out" >&2
  exit 2
fi
revision="$(git rev-parse HEAD)"
built="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ldflags="-s -w -X main.buildVersion=$version -X main.buildRev=$revision -X main.buildDate=$built"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT HUP INT TERM

for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  os="${target%/*}"
  arch="${target#*/}"
  name="frp-otp_${version#v}_${os}_${arch}"
  package="$stage/$name"
  mkdir -p "$package/examples"
  suffix=""
  if [ "$os" = windows ]; then suffix=".exe"; fi
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$ldflags" -o "$package/frp-otp$suffix" .
  cp README.md LICENSE CHANGELOG.md "$package/"
  cp examples/frps.toml "$package/examples/"
  # Never include a maintainer's local OTP secret in a release package.
  printf '{\n  "BindAddress": "127.0.0.1:9000",\n  "secret": "",\n  "grant_duration": "4h",\n  "trust_networks": ["10.0.0.0/8", "192.168.0.0/16"]\n}\n' > "$package/frp.otp.json"
  if [ "$os" = windows ]; then
    (cd "$stage" && zip -qr "$out/$name.zip" "$name")
  else
    tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
  fi
  printf 'Built %s\n' "$name"
done
(cd "$out" && sha256sum ./*.tar.gz ./*.zip > SHA256SUMS && sha256sum -c SHA256SUMS)
