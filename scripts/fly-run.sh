#!/bin/bash
set -euo pipefail

VENDOR_ID="$(lscpu -J | jq -r -e '.lscpu[] | select(.field == "Vendor ID:") | .data')"

case "$VENDOR_ID" in
  GenuineIntel)
    CPU_VENDOR=intel
    ;;
  AuthenticAMD)
    CPU_VENDOR=amd
    ;;
  *)
    echo "unknown CPU vendor ID: $VENDOR_ID" >&2
    exit 1
    ;;
esac

RESULTS="results-$CPU_VENDOR-$FLY_REGION"

./benchmarks/benchmark.py ebpf ebpf-4gb ebpf-unchecked go-gvisor native wasmtime -o "$RESULTS"
cp /proc/cpuinfo "$RESULTS/cpuinfo.txt"
cp /proc/meminfo "$RESULTS/meminfo.txt"
uname -a > "$RESULTS/uname.txt"
tar -czvf "$RESULTS.tar.gz" "$RESULTS"
