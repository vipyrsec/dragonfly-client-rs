# dragonfly-client-rs

Modular compute nodes capable of scanning packages and sending results upstream
to a control server, written in Rust.

## Set up

This section goes over how to set up a client instance locally and via Docker.

> Refer to the [Environment variables](#environment-variables) section for
> information on what environment variables are necessary.

### Local

#### Requirements

- [Rust](https://www.rust-lang.org/tools/install)
- [YARA](https://yara.readthedocs.io/en/stable/gettingstarted.html#compiling-and-installing-yara)

#### 1. Set the appropriate environment variable pointing to the YARA installation

```bash
export YARA_LIBRARY_PATH='/path/to/yara/libs'
```

#### 2. Build the binary with `cargo`

```bash
cargo build --release
```

#### 3. Run the built binary

```bash
./target/release/dragonfly-client-rs
```

### Docker

#### Requirements

- [Docker Engine](https://docs.docker.com/engine/install/)

#### 1. Build and tag the image

```bash
docker build --tag vipyrsec/dragonfly-client-rs:latest .
```

#### 2. Run the container

```bash
docker run --name dragonfly-client-rs vipyrsec/dragonfly-client-rs:latest
```

### Docker Compose

#### Requirements

- [Docker Engine](https://docs.docker.com/engine/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)

#### Run the service

```bash
docker compose up
```

### How it works: Overview

The follow is a brief overview of how the client works. A more extensive
writeup can be found towards the bottom of this page.

The client is comprised of a few discrete components, each running
independently. These are the scanning threadpool, the loader thread, and the
sender thread.

- The Scanning Threadpool - Downloads and scans the releases.
- The Loader Thread - This thread is responsible for requesting jobs from the API and submitting them to the threadpool.

### Performance, efficiency, and optimization

The client aims to be highly configurable to suit a variety of host machines.
The scanner processes one package and one distribution at a time. Compressed
downloads, expanded archives, individual scan targets, archive entry counts,
and distributions per package are bounded independently. The defaults target
a 512 MiB background-worker container while preserving substantial headroom
for compiled YARA rules, ZIP metadata, allocator overhead, and filesystem
cache.

### How it works: Detailed Breakdown

This section attempts to describe in detail how the client works under the
hood, and how the various configuration parameters come into play.

The client can be broken down into a few discrete components: The scanner
threads, the loader thread, the sender thread. We will first explore in detail
the workings of each of these components in isolation and then how they all fit
together.

The scanner thread(s) are what do most of the heavy lifting. They use bindings
to the C YARA library, and most of this code can be found in `scanner.rs`. The
way this program models PyPI data structure is as so: There are "packages" (or
"releases") which is a name/version specifier combination. These "packages" are
comprised of several "distributions" in the form of gzipped tarballs or wheels
(which behave similarly to zip files, hence the use of the `zip` crate). Each
distribution is comprised of a flat sequence of files (the hierarchical nature
of the traditional file/folder system has been flatted for our use case). The
main entry point interface to the scanner logic is via
`scan_all_distributions`. This loops over the download URLs sequentially,
stages each compressed distribution on temporary disk, validates its resource
limits, and extracts it. Files are scanned individually from disk by YARA.
Only the highest-scoring file and unique matched rules are retained for each
distribution.

The loader thread's primary responsibility is to request a bunch of jobs from
the API and spawn threadpool tasks on a timer. It will perform a "bulk job
request" (`POST /jobs`) API request to retrieve N jobs from the API, where
N can be configured via the `DRAGONFLY_BULK_SIZE` environment variable. The
client will make these bulk requests at an interval defined by
the`DRAGONFLY_LOAD_DURATION` environment variable. The jobs returned by the API
endpoint will then be spawned as tasks in the threadpool. This process repeats for
the duration of the program.

The client authenticates every Dragonfly API request with a Cloudflare Access
service token. The source code of the YARA rules is compiled (very much like
compiling regex) and stored in shared state. Then, the necessary threads are
spawned. Once a threadpool task has finished scanning, it sends its results
over the Dragonfly HTTP API.

### Environment variables

Below are a list of environment variables that need to be configured, and what
they do

<!-- markdownlint-disable MD013 -->
| Variable                              | Default                          | Description                                                                     |
| ------------------------------------- | -------------------------------- | ------------------------------------------------------------------------------- |
| `DRAGONFLY_BASE_URL`                  | `https://dragonfly.vipyrsec.com` | The base API URL for the mainframe server                                       |
| `DRAGONFLY_CF_ACCESS_CLIENT_ID`       |                                  | Environment-specific Cloudflare Access service-token client ID                  |
| `DRAGONFLY_CF_ACCESS_CLIENT_SECRET`   |                                  | Environment-specific Cloudflare Access service-token client secret              |
| `DRAGONFLY_THREADS`                   | Available parallelism / `1`      | Attempts to auto-detect the amount of threads, or defaults to 1 if not possible |
| `DRAGONFLY_LOAD_DURATION`             | 60                               | Seconds to wait between each API job request                                    |
| `DRAGONFLY_BULK_SIZE`                 | 20                               | The amount of jobs to request at once                                           |
| `DRAGONFLY_MAX_ARCHIVE_ENTRIES`       | 4096                             | Maximum number of entries in one archive                                        |
| `DRAGONFLY_MAX_DISTRIBUTIONS`         | 32                               | Maximum number of distributions in one package                                  |
| `DRAGONFLY_MAX_DOWNLOAD_SIZE`         | 33554432                         | Maximum compressed distribution size in bytes                                   |
| `DRAGONFLY_MAX_EXPANDED_SIZE`         | 67108864                         | Maximum total expanded distribution size in bytes                               |
| `DRAGONFLY_MAX_SCAN_SIZE`             | 16777216                         | Maximum individual file size passed to YARA in bytes                            |
<!-- markdownlint-enable MD013 -->
