#!/bin/bash
set -euo pipefail

BASEDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && echo "$PWD")"

if [[ "$PWD" == "$BASEDIR/"* ]]; then
  WORKDIR="${PWD#$BASEDIR/}"
else
  WORKDIR=""
fi

exec docker run \
  --device /dev/net/tun \
  --cap-add NET_ADMIN \
  --rm -it \
  -v ebpfjit-cargo-registry:/root/.cargo/registry \
  -v "$BASEDIR:/work" \
  -w "/work/$WORKDIR" \
  ebpfjit "$@"
