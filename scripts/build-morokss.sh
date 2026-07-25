#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
abi="${1:-arm64-v8a}"
sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$sdk" ]]; then
  echo "Set ANDROID_SDK_ROOT first" >&2
  exit 1
fi
ndk="${ANDROID_NDK_HOME:-$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n1)}"
toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"

case "$abi" in
  arm64-v8a) goarch=arm64; cc=aarch64-linux-android26-clang ;;
  armeabi-v7a) goarch=arm; cc=armv7a-linux-androideabi26-clang; export GOARM=7 ;;
  x86_64) goarch=amd64; cc=x86_64-linux-android26-clang ;;
  x86) goarch=386; cc=i686-linux-android26-clang ;;
  *) echo "Unsupported ABI: $abi" >&2; exit 1 ;;
esac

output="$repo/core/src/main/jniLibs/$abi/libmorokss.so"
mkdir -p "$(dirname "$output")"
(cd "$repo/third_party/morokss" && \
  GOOS=android GOARCH="$goarch" CGO_ENABLED=1 CC="$toolchain/$cc" \
    go build -buildmode=pie -trimpath -ldflags="-s -w" \
    -o "$output" ./cmd/morokss-client)
echo "Built $output"
