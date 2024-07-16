#syntax=docker/dockerfile:1.5

ARG DEBIAN_VERSION=bookworm
ARG DEBIAN_VERSION_NUMBER=12
ARG PROJECT=dragonfly-client-rs
ARG RUST_VERSION=1.78

# ====================================================================================================
# Base
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS build-base
ARG PROJECT

WORKDIR /app
COPY .cargo Cargo.toml ./
COPY Cargo.lock Cargo.lock

# ====================================================================================================
# Debug
FROM build-base AS build-debug
ARG PROJECT

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=rust-target-debug,target=/app/target \
  <<EOT
#!/usr/bin/env bash
set -eu

mkdir src
echo 'fn main() {}' > src/main.rs
cargo build --locked
rm src/main.rs target/debug/deps/${PROJECT//-/_}*
EOT

COPY src src
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=rust-target-debug,target=/app/target \
  cargo build --locked && cp /app/target/debug/${PROJECT} /app/${PROJECT}

# ==================================================
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION_NUMBER}:debug-nonroot AS debug
ARG PROJECT

WORKDIR /app

COPY --from=build-debug /app/${PROJECT} ./${PROJECT}

ENTRYPOINT ["./dragonfly-client-rs"]

# ====================================================================================================
# Release
FROM build-base AS build-release
ARG PROJECT

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=rust-target-release,target=/app/target \
  <<EOT
#!/usr/bin/env bash
set -eu

mkdir src
echo 'fn main() {}' > src/main.rs
cargo build --locked --release
rm src/main.rs target/release/deps/${PROJECT//-/_}*
EOT

COPY src src
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=rust-target-release,target=/app/target \
  cargo build --locked --release && cp /app/target/release/${PROJECT} /app/${PROJECT}

# ==================================================
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION_NUMBER}:nonroot AS release
ARG PROJECT

WORKDIR /app

COPY --from=build-release /app/${PROJECT} ./${PROJECT}

ENTRYPOINT ["./dragonfly-client-rs"]
