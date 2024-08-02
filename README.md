# dragonfly-client-rs

`dragonfly-client-rs` uses [Yara](https://virustotal.github.io/yara/) to scan
code pulled from the [Python Package Index](https://pypi.org/) (PYPI). It polls
for work from
[`dragonfly-mainframe`](https://github.com/vipyrsec/dragonfly-mainframe).

## Running `dragonfly-client-rs`

## Requirements

- [Docker Engine](https://docs.docker.com/engine/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [Environment Variables](#environment-variables)

## Run

```bash
docker compose up
```

Note: to build and run without Docker Compose, see [build
locally](docs/building_locally.md).

### Environment variables

Variables without a default are **required**. For more information on how to
use these, see [tuning](docs/tuning.md).

| Variable                  | Default                          | Description                                  |
|---------------------------|----------------------------------|----------------------------------------------|
| `DRAGONFLY_BASE_URL`      | `https://dragonfly.vipyrsec.com` | The base API URL for the mainframe server    |
| `DRAGONFLY_AUTH0_DOMAIN`  | `vipyrsec.us.auth0.com`          | The auth0 domain that requests go to         |
| `DRAGONFLY_AUDIENCE`      | `https://dragonfly.vipyrsec.com` | Auth0 Audience field                         |
| `DRAGONFLY_CLIENT_ID`     |                                  | Auth0 client ID                              |
| `DRAGONFLY_CLIENT_SECRET` |                                  | Auth0 client secret                          |
| `DRAGONFLY_USERNAME`      |                                  | Provisioned username                         |
| `DRAGONFLY_PASSWORD`      |                                  | Provisioned password                         |
| `DRAGONFLY_LOAD_DURATION` | `60`                             | Seconds to wait between each API job request |
| `DRAGONFLY_MAX_SCAN_SIZE` | `128_000_000`                    | Maximum distribution size in bytes to scan   |
