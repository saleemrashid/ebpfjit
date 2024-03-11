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
      -e 's/@llvm\.ctlz\.i64\((i64 [^,]+), i1 false\)/@__ctzti2(\1)/g' \
      -e 's/@llvm\.memset\.p0\.i64\((.*), i1 false\)/@memset(\1)/g' \
      -e 's/@llvm\.memcpy\.p0\.p0\.i64\((.*), i1 false\)/@memcpy(\1)/g' \
      -e 's/^declare i32 @llvm\.ctlz\.i32.*$/declare i32 @__ctzsi2(i32)/g' \
      -e 's/^declare i64 @llvm\.ctlz\.i64.*$/declare i64 @__ctzti2(i64)/g' \
      "$output" > "$name-bpf.ll"
    llc -O=3 -march=bpfel -mcpu=v4 -filetype=obj -bpf-stack-size=131072 "$name-bpf.ll" -o "$name-bpf.o"

    (
      set -x
      ../compile.py "$name-bpf.o" > "$name.ll"
      clang -O3 -c "$name.ll" -o "$name.o"
    )
  done
