#!/bin/bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Not running under Docker, refusing to patch rustlib!" >&2
  exit 1
fi

# rust-lang/rust commit 46b180ec2452d388c5d9c14009442e2e0beb01d7
PATCHES=(
  vendor/core-inline-pad-integral.patch
  vendor/core-inline-unicode-printable-check.patch
)

for patch in "${PATCHES[@]}"; do
  # This is terrible, but we can't tell Cargo to find libcore elsewhere
  patch -R -d "$(rustc --print sysroot)/lib/rustlib/src/rust" --strip=1 < "$patch" || true
  patch -N -d "$(rustc --print sysroot)/lib/rustlib/src/rust" --strip=1 < "$patch"
done
