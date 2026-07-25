#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
jni_root="$repository/android/app/src/main/jniLibs"
ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [[ -z "$ndk_root" ]]; then
  echo "Set ANDROID_NDK_HOME to an installed Android NDK" >&2
  exit 1
fi
toolchain="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin"

build_target() {
  local abi="$1"
  local goarch="$2"
  local compiler="$3"
  local goarm="${4:-}"
  local output="$jni_root/$abi/libmorokss.so"

  mkdir -p "$(dirname "$output")"
  if [[ -n "$goarm" ]]; then
    GOOS=android GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=1 CC="$toolchain/$compiler" \
      go build -buildmode=pie -trimpath -ldflags="-s -w" -o "$output" ./cmd/morokss-client
  else
    GOOS=android GOARCH="$goarch" CGO_ENABLED=1 CC="$toolchain/$compiler" \
      go build -buildmode=pie -trimpath -ldflags="-s -w" -o "$output" ./cmd/morokss-client
  fi
  echo "Built $abi: $output"
}

cd "$repository"
build_target arm64-v8a arm64 aarch64-linux-android26-clang
build_target armeabi-v7a arm armv7a-linux-androideabi26-clang 7
build_target x86_64 amd64 x86_64-linux-android26-clang
build_target x86 386 i686-linux-android26-clang
