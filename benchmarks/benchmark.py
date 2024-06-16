#!/usr/bin/env python3
import argparse
import enum
import re
import subprocess
from pathlib import Path
from subprocess import check_call, check_output
from typing import Iterable, Mapping

from runner import Runner


class Mode(enum.Enum):
    NATIVE = "native"
    WASMTIME = "wasmtime"
    EBPF = "ebpf"
    EBPF_UNCHECKED = "ebpf-unchecked"
    EBPF_4GB = "ebpf-4gb"
    GO_GVISOR = "go-gvisor"


RESPONSES: Mapping[Mode, re.Pattern[bytes]] = {
    Mode.NATIVE: re.compile(rb"\AHello from (aarch64|x86_64)\Z"),
    Mode.WASMTIME: re.compile(rb"\AHello from wasm32\Z"),
    Mode.EBPF: re.compile(rb"\AHello from eBPF\Z"),
    Mode.EBPF_UNCHECKED: re.compile(rb"\AHello from eBPF\Z"),
    Mode.EBPF_4GB: re.compile(rb"\AHello from eBPF\Z"),
    Mode.GO_GVISOR: re.compile(rb"\AHello from Go\Z"),
}


def apache_bench(runner: Runner, dir: Path, requests: int, concurrency: int) -> None:
    for i in range(25):
        stem = f"ab-{requests}-{concurrency}-{i + 1:02}"
        check_call(
            [
                "ab",
                "-n",
                str(requests),
                "-c",
                str(concurrency),
                "-r",
                "-e",
                dir / f"{stem}.csv",
                "-g",
                dir / f"{stem}.tsv",
                f"{runner.url}/",
            ]
        )


def run(mode: Mode, dir: Path, wrapper: Iterable[str] = ()) -> None:
    with Runner([*wrapper, f"./runner-{mode.value}"]) as runner:
        response = check_output(["curl", "-sSf", f"{runner.url}/health"]).strip()
        if not RESPONSES[mode].match(response):
            raise Exception(f"unexpected response: {response!r}")

        for requests, concurrency in (
            # (2500, 500),
            (2500, 1000),
            # (5000, 500),
            # (5000, 1000),
            # (5000, 5000),
            # (10000, 500),
            # (10000, 1000),
            # (10000, 5000),
        ):
            apache_bench(runner, dir, requests, concurrency)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="+", type=Mode)
    parser.add_argument("-o", "--output-directory", type=Path, required=True)
    parser.add_argument("-p", "--perf", action="store_true")
    args = parser.parse_args()

    if args.perf:
        wrapper = ["perf", "record", "-g", "-F", "999"]
    else:
        wrapper = []

    for mode in args.mode:
        dir = args.output_directory / mode.value
        dir.mkdir(parents=True, exist_ok=False)
        run(mode, dir, wrapper)


if __name__ == "__main__":
    main()
