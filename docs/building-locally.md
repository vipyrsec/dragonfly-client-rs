# How to Build and Run `dragonfly-client-rs` Locally
## Requirements

- [Rust](https://www.rust-lang.org/tools/install)
- [YARA](https://yara.readthedocs.io/en/stable/gettingstarted.html#compiling-and-installing-yara)

## Set the appropriate environment variable pointing to the YARA installation
```bash
export YARA_LIBRARY_PATH='/path/to/yara/libs'
```

## Build the binary with `cargo`

```bash
cargo build --release
```

## Run the built binary

```bash
./target/release/dragonfly-client-rs
```
