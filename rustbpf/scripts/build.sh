#!/bin/bash
set -euo pipefail

BPF_STACK_SIZE=131072

TARGETS=("$@")

if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  TARGETS=($(cargo metadata --format-version 1 --no-deps \
    | jq -r '.packages[].targets[] | select(.kind | index("bin")) | .name'))
fi

CARGOFLAGS=(
  --message-format json-render-diagnostics
  --release
)
RUSTCFLAGS=(
  -C link-args=--emit=llvm-ir
)

while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--" ]]; then
    shift
    break
  fi

  CARGOFLAGS+=("$1")
  shift
done
RUSTCFLAGS+=("$@")

scripts/patch-rustlib.sh
scripts/vendor-smoltcp.sh

clang -O3 -S -emit-llvm ../tests/shim.c -o shim.ll

for target in "${TARGETS[@]}"; do
  output="$(cargo rustc --bin "$target" "${CARGOFLAGS[@]}" -- "${RUSTCFLAGS[@]}" \
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
    -e 's/^define weak hidden noundef /define internal noundef /g' \
    "$output" > "$name-bpf.ll"
  llc -O=3 -march=bpfel -mcpu=v4 -filetype=obj -bpf-stack-size="$BPF_STACK_SIZE" "$name-bpf.ll" -o "$name-bpf.o"
  ../compile.py "$name-bpf.o" | llvm-link -S - shim.ll -o "$name.ll"
  clang -O3 -c "$name.ll" -o "$name.o"
  libname="${name%/*}/lib${name##*/}.a"
  rm -f "$libname"
  ar -rcD "$libname" "$name.o"
done
