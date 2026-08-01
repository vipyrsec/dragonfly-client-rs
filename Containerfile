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
# YARA_COMMIT The immutable upstream commit corresponding to YARA_VERSION
ARG YARA_COMMIT=7ff39042be5c63682a037e13a75221d59393cf8b
# YARA_SHA256 The verified digest of the immutable upstream source archive
ARG YARA_SHA256=70e9d13905f5687a2c2731b64a8073001d5f1909967f81937ab27fe10006ec97

# build-base contains the reviewed native YARA build used by later stages.
FROM rust:$RUST_VERSION-$DEBIAN_VERSION AS build-base
ARG PROJECT

ARG RUSTFLAGS
ARG YARA_COMMIT
ARG YARA_SHA256
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

archive_filename="yara-$YARA_COMMIT.tar.gz"
curl --fail --location --silent --show-error \
  "https://github.com/VirusTotal/yara/archive/$YARA_COMMIT.tar.gz" \
  --output "$archive_filename"
printf '%s  %s\n' "$YARA_SHA256" "$archive_filename" | sha256sum --check --strict
tar -xzf "$archive_filename"
EOT

WORKDIR /build/yara-$YARA_COMMIT

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
  cargo build --locked --release && cp "/app/target/release/$PROJECT" "/app/$PROJECT"

# release The release build
FROM gcr.io/distroless/cc-debian$DEBIAN_VERSION_NUMBER:nonroot AS release
ARG PROJECT

WORKDIR /app

COPY --from=build-release "/app/$PROJECT" "./$PROJECT"

ENTRYPOINT ["./dragonfly-client-rs"]
