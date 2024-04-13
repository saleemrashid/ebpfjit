#!/bin/bash
set -euo pipefail

BASEDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && echo "$PWD")"

if [[ "$PWD" == "$BASEDIR/"* ]]; then
  WORKDIR="${PWD#$BASEDIR/}"
else
  WORKDIR=""
fi

exec docker run --privileged --rm -it -v "$BASEDIR:/work" -w "/work/$WORKDIR" ebpfjit "$@"
