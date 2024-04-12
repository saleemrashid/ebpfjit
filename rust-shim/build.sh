#!/bin/bash
set -euo pipefail

TARGET=aarch64-unknown-linux-gnu

outputs=($(RUSTFLAGS="--emit=llvm-bc -C codegen-units=1" cargo build \
  --message-format json-render-diagnostics \
  --release \
  --target "$TARGET" \
  -Z build-std=std,panic_abort \
  | jq -s -r '.[] | select(.reason == "compiler-artifact")
        | select(.target.name != "panic_unwind")
        | .filenames[]
        | select(endswith(".rmeta"))
        | sub("/lib(?<name>.*)\\.rmeta$"; "/\(.name).bc")'))

llvm-link "${outputs[@]}" -o shim.bc
