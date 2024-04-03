#!/bin/sh
exec docker run --rm -it -v "$(PWD)/..:/work" -w /work/rustbpf ebpfjit "$@"
