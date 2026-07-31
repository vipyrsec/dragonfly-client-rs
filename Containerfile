# syntax=docker/dockerfile:latest
# hadolint global shell=bash

# DEBIAN_VERSION The version name of Debian to use for the base images
ARG DEBIAN_VERSION=trixie
# DEBIAN_VERSION The version number of Debian to use for the base images
ARG DEBIAN_VERSION_NUMBER=13
# DEBIAN_FRONTEND The frontend of the Apt package manager to use
ARG DEBIAN_FRONTEND=noninteractive
# PROJECT The name of this project (only to ensure the project name isn't misspelt in multiple commands)
ARG PROJECT=dragonfly-client-rs
# RUST_VERSION The version of Rust to use for the base image for the build stages
ARG RUST_VERSION=1.91
# RUSTFLAGS The compile-time flags to pass to the Rust compiler when compiling the project
ARG RUSTFLAGS="-L/usr/local/lib"
# YARA_VERSION The version of YARA against which to link the project
ARG YARA_VERSION=4.5.4
# OPENGREP_VERSION The reviewed OpenGrep release used only by the shadow target
ARG OPENGREP_VERSION=1.26.0
# OPENGREP_SHA256 The verified linux-amd64 release digest
ARG OPENGREP_SHA256=40c21299eeddabf743b856daa843d24f9d4a027130671cd45b3b21776fd9ab26

# opengrep-binary is reachable only from the staging shadow image target.
FROM rust:$RUST_VERSION-$DEBIAN_VERSION AS opengrep-binary
ARG OPENGREP_SHA256
ARG OPENGREP_VERSION
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN <<EOT
#!/usr/bin/env bash
set -euo pipefail

curl --fail --location --silent --show-error \
  "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86" \
  --output /opengrep
printf '%s  /opengrep\n' "${OPENGREP_SHA256}" > /tmp/opengrep.sha256
sha256sum --check --strict /tmp/opengrep.sha256
chmod 0755 /opengrep
EOT

# build-base The base for standard and shadow Rust builds, including YARA.
FROM rust:$RUST_VERSION-$DEBIAN_VERSION AS build-base
ARG PROJECT

ARG RUSTFLAGS
ARG YARA_VERSION
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN <<EOT
#!/usr/bin/env bash
set -eu

apt-get -q update
apt-get -qy --no-install-recommends install \
  'curl=8.14.1-2+deb13u4' \
  'libclang-dev=1:19.0-63'
rm -rf /var/lib/apt/lists/*
EOT

WORKDIR /build

RUN <<EOT
#!/usr/bin/env bash
set -euo pipefail

archive_filename="yara-$YARA_VERSION.tar.gz"
curl -sL "https://github.com/VirusTotal/yara/archive/refs/tags/v$YARA_VERSION.tar.gz" -o "$archive_filename"
tar -xzf "$archive_filename"
EOT

WORKDIR /build/yara-$YARA_VERSION

RUN ./bootstrap.sh && ./configure && make && make install

WORKDIR /app
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

# build-debug The build stage for the debug build
FROM build-base AS build-debug
ARG PROJECT
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=rust-target-debug,target=/app/target \
  <<EOT
#!/usr/bin/env bash
set -eu

mkdir src
echo 'fn main() {}' > src/main.rs
cargo build --locked
rm src/main.rs "target/debug/deps/${PROJECT//-/_}"*
EOT

COPY src src
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=rust-target-debug,target=/app/target \
  cargo build --locked && cp "/app/target/debug/$PROJECT" "/app/$PROJECT"

# debug The debug build
FROM gcr.io/distroless/cc-debian$DEBIAN_VERSION_NUMBER:debug-nonroot AS debug
ARG PROJECT

WORKDIR /app

COPY --from=build-debug "/app/$PROJECT" "./$PROJECT"

ENTRYPOINT ["./dragonfly-client-rs"]

# build-release The build stage for the release build
FROM build-base AS build-release
ARG PROJECT
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=rust-target-release,target=/app/target \
  <<EOT
#!/usr/bin/env bash
set -eu

mkdir src
echo 'fn main() {}' > src/main.rs
cargo build --locked --release
rm src/main.rs "target/release/deps/${PROJECT//-/_}"*
EOT

COPY src src
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=rust-target-release,target=/app/target \
  cargo build --locked --release --bin "$PROJECT" \
  && cp "/app/target/release/$PROJECT" "/app/$PROJECT"

# release The release build
FROM gcr.io/distroless/cc-debian$DEBIAN_VERSION_NUMBER:nonroot AS release
ARG PROJECT

WORKDIR /app

COPY --from=build-release "/app/$PROJECT" "./$PROJECT"

ENTRYPOINT ["./dragonfly-client-rs"]

# build-opengrep-release is reachable only from the staging shadow image.
FROM build-release AS build-opengrep-release

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=rust-target-release,target=/app/target \
  cargo build --locked --release --bin opengrep-shadow \
  && cp /app/target/release/opengrep-shadow /app/opengrep-shadow

# opengrep-release The staging-only shadow worker. The standard release image
# above intentionally does not contain the OpenGrep executable.
FROM gcr.io/distroless/cc-debian$DEBIAN_VERSION_NUMBER:nonroot AS opengrep-release

WORKDIR /app

COPY --from=build-opengrep-release /app/opengrep-shadow ./opengrep-shadow
COPY --from=opengrep-binary /opengrep /usr/local/bin/opengrep

ENTRYPOINT ["./opengrep-shadow"]
