# dragonfly-rs

Modular compute nodes capable of scanning packages and sending results upstream to a control server, written in Rust

## Set up
This section goes over how to set up a client instance locally and via Docker.

### Local

Requirements
- [Rust](https://www.rust-lang.org/learn/get-started)
- [yara](https://yara.readthedocs.io/en/stable/gettingstarted.html#compiling-and-installing-yara)
- [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)

Clone the repository and change directory into it:
```
git clone https://github.com/vipyrsec/dragonfly-rs.git
cd dragonfly-rs
```
Build the binary with cargo:
```
cargo build --release
```
Finally, run the built binary:
```
./target/release/dragonfly-rs
```

### Docker

Requirements:
- [Docker Engine](https://docs.docker.com/get-docker/)
- [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)

Clone the repository and change directory into it:
```
git clone https://github.com/vipyrsec/dragonfly-rs.git
cd dragonfly-rs
```
Build the Docker image and tag it:
```
docker build --tag dragonfly-rs .
```
Run the Docker image:
```
docker run dragonfly-rs
```
