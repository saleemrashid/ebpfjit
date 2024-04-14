#!/bin/bash
set -euo pipefail

if [[ "${SAFE_TO_PATCH_RUSTLIB-}" != "1" ]]; then
  echo "Need SAFE_TO_PATCH_RUSTLIB=1" >&2
  exit 1
fi

# rust-lang/rust commit 46b180ec2452d388c5d9c14009442e2e0beb01d7
PATCHES=(
  vendor/core-inline-pad-integral.patch
  vendor/core-inline-unicode-printable-check.patch
)

# This is terrible, but we can't tell Cargo to find libcore elsewhere
DIR="$(rustc --print sysroot)/lib/rustlib/src/rust"

for patch in "${PATCHES[@]}"; do
  # Try reversing first
  patch -R -d "$DIR" --strip=1 < "$patch" 2>/dev/null || true
  patch -N -d "$DIR" --strip=1 < "$patch"
done
