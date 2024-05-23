#!/bin/bash
set -euo pipefail

BPF_STACK_SIZE=131072

PACKAGES=(
  netstack
)

CARGOFLAGS=(
  --target bpfel-unknown-none
  -Z build-std=core,alloc
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

clang -O3 -S -emit-llvm -fPIC ../tests/shim.c -o shim.ll
clang -O3 -S -emit-llvm -DSHIM_UNCHECKED -fPIC ../tests/shim.c -o shim-unchecked.ll
clang -O3 -S -emit-llvm -fPIC ../4gb/shim.c -o shim-4gb.ll

ARCHFLAGS_4GB=()
case "$(clang --print-target-triple)" in
  aarch64-*)
    ARCHFLAGS_4GB=(
      -mcmodel=small
    )
    ;;
  x86_64-*)
    ARCHFLAGS_4GB=(
      -mcmodel=large
    )
    ;;
esac

for package in "${PACKAGES[@]}"; do
  output="$(cargo rustc -p "$package" --bin "$package" "${CARGOFLAGS[@]}" -- "${RUSTCFLAGS[@]}" \
    | jq -e -s -r 'map(select(.reason == "compiler-artifact") | .executable) | last')"
  name="target/${package}"
  libname="target/lib$package"

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
  ../compile.py "$name-bpf.o" > "$name.ll"
  llvm-link --internalize "$name.ll" shim.ll -o "$name.bc"
  llvm-link --internalize "$name.ll" shim-unchecked.ll -o "$name-unchecked.bc"
  llvm-link --internalize "$name.ll" shim-4gb.ll -o "$name-4gb.bc"
  clang -O3 -c -fPIC "$name.bc" -o "$name.o"
  clang -O3 -c -fPIC "$name-unchecked.bc" -o "$name-unchecked.o"
  rm -f "$libname.a"
  ar -rcD "$libname.a" "$name.o"
  rm -f "$libname-unchecked.a"
  ar -rcD "$libname-unchecked.a" "$name-unchecked.o"
  clang -O3 -shared -fPIC -nostartfiles "${ARCHFLAGS_4GB[@]}" "$name-4gb.bc" -T../4gb/script.ld -o "$libname-4gb.so"
done
