FROM rust:1.69-bullseye as builder

RUN USER=root cargo new --bin dragonfly-rs
WORKDIR /dragonfly-rs

RUN apt update && apt install -y curl libclang-dev

RUN curl -sL https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.1.tar.gz | tar xz && cd yara-4.3.1 && ./bootstrap.sh && ./configure && make && make install

COPY .cargo/ .cargo/
COPY Cargo.toml .
COPY Cargo.lock .

ARG dragonfly_base_url 
ENV DRAGONFLY_BASE_URL=$dragonfly_base_url

RUN RUSTFLAGS='-L/usr/local/lib' cargo build --release

RUN rm target/release/deps/dragonfly_rs*

COPY src/ src/
RUN RUSTFLAGS='-L/usr/local/lib' cargo build --release

###################################################################
FROM gcr.io/distroless/cc as runner

COPY --from=builder /dragonfly-rs/target/release/dragonfly-rs ./

CMD ["./dragonfly-rs"]
