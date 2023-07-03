# dragonfly-client-rs

Modular compute nodes capable of scanning packages and sending results upstream to a control server, written in Rust.

## Set up

This section goes over how to set up a client instance locally and via Docker.

> Refer to the [Environment variables](#environment-variables) section for information on what environment variables are necessary.

### Local

#### Requirements

- [Rust](https://www.rust-lang.org/tools/install)
- [YARA](https://yara.readthedocs.io/en/stable/gettingstarted.html#compiling-and-installing-yara)

#### 1. Set the appropriate environment variable pointing to the YARA installation
```sh
export YARA_LIBRARY_PATH='/path/to/yara/libs'
```

#### 2. Build the binary with `cargo`

```sh
cargo build --release
```

#### 3. Run the built binary

```sh
./target/release/dragonfly-client-rs
```

### Docker

#### Requirements

- [Docker Engine](https://docs.docker.com/engine/install/)

#### 1. Build and tag the image

```sh
docker build --tag vipyrsec/dragonfly-client-rs:latest .
```

#### 2. Run the container

```sh
docker run --name dragonfly-client-rs vipyrsec/dragonfly-client-rs:latest
```

### Docker Compose

#### Requirements

- [Docker Engine](https://docs.docker.com/engine/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)

#### Run the service

```
docker compose up
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
