# dragonfly-rs

Modular compute nodes capable of scanning packages and sending results upstream to a control server, written in Rust

## Set up
This section goes over how to set up a client instance locally and via Docker.

**Please refer to the "Environment variables" section towards the bottom of this page for information on what environment variables are necessary**

### Local

Requirements
- [Rust](https://www.rust-lang.org/learn/get-started)
- [yara](https://yara.readthedocs.io/en/stable/gettingstarted.html#compiling-and-installing-yara)
- [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)


Set the appropriate environment variable pointing to the yara installation:
```
export RUSTFLAGS='-L/path/to/yara'
```

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

### Environment variables
Below are a list of environment variables that need to be configured, and what they do

| Variable                  | Default                          | Description                               |
| ------------------------- | -------------------------------- | ----------------------------------------- |
| `DRAGONFLY_BASE_URL`      | `https://dragonfly.vipyrsec.com` | The base API URL for the mainframe server |
| `DRAGONFLY_AUTH0_DOMAIN`  | `vipyrsec.us.auth0.com`          | The auth0 domain that requests go to      |
| `DRAGONFLY_AUDIENCE`      | `https://dragonfly.vipyrsec.com` | Auth0 Audience field                      |
| `DRAGONFLY_CLIENT_ID`     |                                  | Auth0 client ID                           |
| `DRAGONFLY_CLIENT_SECRET` |                                  | Auth0 client secret                       |
| `DRAGONFLY_USERNAME`      |                                  | Provisioned username                      |
| `DRAGONFLY_PASSWORD`      |                                  | Provisioned password                      |
