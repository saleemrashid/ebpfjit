FROM ubuntu:22.04 as base

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked <<EOT
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates \
  curl \
  software-properties-common
apt-add-repository ppa:deadsnakes/ppa
. /etc/os-release
curl -LSf "https://apt.llvm.org/llvm-snapshot.gpg.key" -o /etc/apt/keyrings/apt.llvm.org.asc
echo > /etc/apt/sources.list.d/apt.llvm.org.list \
  "deb [signed-by=/etc/apt/keyrings/apt.llvm.org.asc] https://apt.llvm.org/${UBUNTU_CODENAME}/ llvm-toolchain-${UBUNTU_CODENAME}-18 main"
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
  python3.12-venv \
  libz-dev \
  libzstd-dev
EOT

ENV PATH="/usr/lib/llvm-18/bin:$PATH"
WORKDIR /work

FROM base as python

RUN --mount=type=cache,target=/root/.cache/pip <<EOT
ln -s "$(which python3.12)" /usr/local/bin/python3
python3 -m ensurepip --altinstall
python3 -m pip install pipenv
EOT

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=Pipfile,target=Pipfile \
    --mount=type=bind,source=Pipfile.lock,target=Pipfile.lock <<EOT
python3 -m pipenv install --system --deploy  
EOT

FROM base

ENV RUSTUP_TOOLCHAIN=nightly-2024-03-09
ENV PATH="/root/.cargo/bin:$PATH"

RUN <<EOT
curl --proto "=https" --tlsv1.3 -Sf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
rustup component add rust-src
cargo install bpf-linker --no-default-features
EOT

VOLUME ["/root/.cargo/registry"]

COPY --link --from=python /usr/local/bin /usr/local/bin
COPY --link --from=python /usr/local/lib/python3.12 /usr/local/lib/python3.12
