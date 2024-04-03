#!/bin/bash
set -euo pipefail

SMOLTCP_COMMIT=ca909a27814f8619baf30d5c602a4c865daeccfb

if [[ ! -d vendor/smoltcp ]]; then
  git clone --no-checkout --single-branch https://github.com/smoltcp-rs/smoltcp.git vendor/smoltcp
fi

apply_patches() {
  for patch in "$@"; do
    git apply --check --reverse "$patch" || git apply "$patch"
  done
}

pushd vendor/smoltcp >/dev/null
git checkout "$SMOLTCP_COMMIT"
apply_patches ../smoltcp-inline-tcpoption-emit.patch
popd >/dev/null
