#!/bin/bash
set -euo pipefail

cargoflags=(
    --message-format json-render-diagnostics
    --release
)
rustcflags=(
    -C link-args=--emit=llvm-ir
)

while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--" ]]; then
    shift
    break
  fi

  cargoflags+=("$1")
  shift
done
rustcflags+=("$@")

cargo metadata --format-version 1 --no-deps \
  | jq -r '.packages[].targets[] | select(.kind | index("bin")) | .name' \
  | while read target; do
    output="$(cargo rustc --bin "$target" "${cargoflags[@]}" -- "${rustcflags[@]}" \
      | jq -s -r 'map(select(.reason == "compiler-artifact") | .executable) | last')"
    name="target/$(basename "$output")"

    # Some hacks to workaround rustc and LLVM bugs
    sed -E \
      -e 's/^declare internal /declare /g' \
      -e 's/@llvm\.ctlz\.i32\((i32 [^,]+), i1 true\)/@__ctzsi2(\1)/g' \
      -e 's/^declare i32 @llvm\.ctlz\.i32.*$/declare i32 @__ctzsi2(i32)/g' \
      "$output" \
    | llc -march=bpfel -mcpu=v3 -filetype=obj -bpf-stack-size=131072 -o "$name.o"

    (
      set -x
      ../compile.py "$name.o" > "$name.ll"
      clang "$name.ll" -o "$name"
    )
  done
