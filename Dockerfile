FROM python:3.12-bookworm as base

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

FROM base as llvm

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked <<EOF
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates \
  curl \
  software-properties-common
. /etc/os-release
curl -LSf "https://apt.llvm.org/llvm-snapshot.gpg.key" -o /etc/apt/keyrings/apt.llvm.org.asc
echo > /etc/apt/sources.list.d/apt.llvm.org.list \
  "deb [signed-by=/etc/apt/keyrings/apt.llvm.org.asc] https://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-18 main"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential \
  curl \
  git \
  jq \
  clang-18 \
  llvm-18-dev \
  libclang-18-dev \
  libpolly-18-dev \
  libz-dev \
  libzstd-dev
EOF

ENV PATH="/usr/lib/llvm-18/bin:$PATH"
WORKDIR /work

FROM base as pipenv

RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked <<EOF
python3 -m pip install pipenv
EOF

RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    --mount=type=bind,source=Pipfile,target=Pipfile \
    --mount=type=bind,source=Pipfile.lock,target=Pipfile.lock <<EOF
python3 -m pipenv install --system --deploy  
EOF

FROM llvm AS build

ENV RUSTUP_TOOLCHAIN=nightly-2024-03-09
ENV PATH="/root/.cargo/bin:$PATH"

RUN <<EOF
curl --proto "=https" --tlsv1.3 -Sf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
rustup component add rust-src
rustup target add wasm32-unknown-unknown
cargo install bpf-linker --no-default-features
EOF

VOLUME ["/root/.cargo/registry"]

COPY --link --from=pipenv /usr/local/bin /usr/local/bin
COPY --link --from=pipenv /usr/local/lib/python3.12 /usr/local/lib/python3.12

# Benchmark images

FROM build AS build-wasmtime

COPY modules modules
COPY runner runner

RUN <<EOF
cd modules
cargo build --target wasm32-unknown-unknown --release
cd ../runner
cargo build --release --features wasmtime
EOF

FROM build AS build-native

COPY modules modules
COPY runner runner

RUN <<EOF
cd runner
cargo build --release --features native
EOF

FROM build-native AS build-ebpf-base

ARG CPUTYPE

COPY *.py .
COPY 4gb/ 4gb/
COPY tests/shim.c tests/shim.c

RUN <<EOF
cd modules
SAFE_TO_PATCH_RUSTLIB=1 scripts/build.sh
EOF

FROM build-ebpf-base AS build-ebpf-default

RUN <<EOF
cd runner
cargo build --release
EOF

FROM build-ebpf-base AS build-ebpf-unchecked

RUN <<EOF
cd runner
cargo build --release --features unchecked
EOF

FROM build-ebpf-base AS build-ebpf-4gb

RUN <<EOF
cd runner
cargo build --release --features 4gb
EOF

FROM golang:1.21-alpine AS build-go-gvisor

RUN --mount=type=cache,target=/go/pkg/mod/,sharing=locked \
    --mount=type=bind,source=misc/gvisor-netstack/go.mod,target=runner/go.mod \
    --mount=type=bind,source=misc/gvisor-netstack/go.sum,target=runner/go.sum <<EOF
cd runner
go mod download -x
EOF

COPY misc/gvisor-netstack runner

RUN --mount=type=cache,target=/go/pkg/mod/,sharing=locked <<EOF
cd runner
go build -o runner
EOF

FROM base AS bench

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked <<EOF
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  apache2-utils \
  curl \
  iproute2 \
  jq \
  linux-perf \
  magic-wormhole
pip3 install pipenv
EOF

WORKDIR /work

RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    --mount=type=bind,source=benchmarks/Pipfile,target=benchmarks/Pipfile \
    --mount=type=bind,source=benchmarks/Pipfile.lock,target=benchmarks/Pipfile.lock <<EOF
cd benchmarks
python3 -m pipenv install --system --deploy
EOF

COPY --link scripts/fly-run.sh fly-run.sh
COPY --link benchmarks benchmarks
COPY --link --from=build-native /work/runner/target/release/runner runner-native
COPY --link --from=build-wasmtime /work/runner/target/release/runner runner-wasmtime
COPY --link --from=build-ebpf-default /work/runner/target/release/runner runner-ebpf
COPY --link --from=build-ebpf-unchecked /work/runner/target/release/runner runner-ebpf-unchecked
COPY --link --from=build-ebpf-4gb /work/modules/target/libnetstack-4gb.so /usr/lib/
COPY --link --from=build-ebpf-4gb /work/runner/target/release/runner runner-ebpf-4gb
COPY --link --from=build-go-gvisor /go/runner/runner runner-go-gvisor

CMD ["bash"]
