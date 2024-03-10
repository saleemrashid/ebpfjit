ARG RUST_TOOLCHAIN=nightly-2024-03-09

FROM ubuntu:22.04 as base

RUN --mount=type=cache,target=/var/cache/apt/archives \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl \
        software-properties-common

FROM base as rust

ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH=/opt/cargo/bin:"$PATH"

ARG RUST_TOOLCHAIN
ENV RUSTUP_TOOLCHAIN="$RUST_TOOLCHAIN"

RUN curl --proto "=https" --tlsv1.3 -Sf https://sh.rustup.rs \
     | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path && \
    rustup component add rust-src

FROM base

RUN --mount=type=cache,target=/var/cache/apt/archives \
    curl -Sf https://apt.llvm.org/llvm-snapshot.gpg.key -o /etc/apt/keyrings/apt.llvm.org.asc && \
    . /etc/os-release && \
    echo "deb [signed-by=/etc/apt/keyrings/apt.llvm.org.asc] https://apt.llvm.org/$UBUNTU_CODENAME/ llvm-toolchain-$UBUNTU_CODENAME-18 main" \
        > /etc/apt/sources.list.d/apt.llvm.org.list && \
    apt-add-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential \
        jq \
        clang-18 \
        llvm-18-dev \
        libclang-18-dev \
        libpolly-18-dev \
        python3.12 \
        python3.12-venv \
        libz-dev \
        libzstd-dev

ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH=/opt/cargo/bin:/usr/lib/llvm-18/bin:"$PATH"

ARG RUST_TOOLCHAIN
ENV RUSTUP_TOOLCHAIN="$RUST_TOOLCHAIN"

COPY --from=rust /opt/rustup/ /opt/rustup/
COPY --from=rust /opt/cargo/ /opt/cargo/

RUN --mount=type=cache,target=/opt/cargo/registry \
    cargo install bpf-linker --no-default-features

WORKDIR /work

COPY Pipfile Pipfile.lock .

RUN --mount=type=cache,target=/root/.cache/pip \
    python3.12 -m ensurepip && \
    python3.12 -m pip install pipenv && \
    pipenv install && \
    rm Pipfile Pipfile.lock

