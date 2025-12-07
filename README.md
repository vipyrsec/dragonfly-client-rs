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

> [!IMPORTANT]
> When building on an arm-based distribution of macOS, be sure to specify
> the following environment variables:
> | Name              | Example Value                             |
> |-------------------|-------------------------------------------|
> | YARA_INCLUDE_DIR  | /opt/homebrew/Cellar/yara/4.3.2_1/include |
> | YARA_LIBRARY_PATH | /opt/homebrew/Cellar/yara/4.3.2_1/lib     |
> | YARA_OPENSSL_DIR  | /opt/homebrew/opt/openssl@3.2             |

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
The environment variables of most value in this regard are as follows:

- `DRAGONFLY_THREADS` defaults to the number of available parallelism, or
  1 if it could not be determined. [This
  page](https://doc.rust-lang.org/stable/std/thread/fn.available_parallelism.html)
  explains in detail how this is calculated, but in short, it is often the
  number of compute cores a machine has. The client will spawn this many
  threads in a threadpool executor to perform concurrent scanning of files.
- `DRAGONFLY_LOAD_DURATION` defaults to `60` seconds. This is the frequency
  with which the loader thread will send an HTTP API request to the Dragonfly
  API requesting N amount of jobs (defined by `DRAGONFLY_BULK_SIZE`).
- `DRAGONFLY_BULK_SIZE` defaults to `20`. This is the amount of jobs the loader
  thread will request from the API at once. Setting this too high may mean the
  scanner threads can't keep up, but setting this too low may mean that
  more CPU time is wasted by idling. `DRAGONFLY_MAX_SCAN_SIZE` defaults to
- `128000000`. The maximum size of downloaded distributions, in bytes. Setting
  this too high may cause clients with low memory to run out of memory and
  crash, setting it too low may mean most packages are not scanned (due to
  being above the size limit).

Many of these options have disadvantages to setting these options to any
extreme (too high or too low), so it's important to tweak it to a good middle
ground that works best in your environment. However, we have tried our best to
provide sensible defaults that will work reasonably efficiently: 20 jobs are
requested from the API every 60 seconds.

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
main entry point interface to the scanner logic is via the
`scan_all_distribution`. This loops over the download URLs of each distribution
of the given job, and attempts to download them. The maximum size of these
downloads, in bytes, is controlled by the `DRAGONFLY_MAX_SIZE` environment
variable (128MB by default) Then, for each distribution downloaded, we loop
over each file in that distribution, load it into memory, and apply the
compiled YARA rules stored in memory against the file contents (this is done by
the underlying C YARA library). Then, the results of each files is stored in
a "distribution scan result" struct that represents the scan results of
a single distribution. This process is repeated for all the distributions in
a package, and are aggregated into a "package scan result" struct. This model
highly reflects PyPI's model of "package -> distributions -> files". This
process allows us to start with the download URLs of each distribution of
a package, and end with the scan results of each file of each distribution of
the given package.

The loader thread's primary responsibility is to request a bunch of jobs from
the API and spawn threadpool tasks on a timer. It will perform a "bulk job
request" (`POST /jobs`) API request to retrieve N jobs from the API, where
N can be configured via the `DRAGONFLY_BULK_SIZE` environment variable. The
client will make these bulk requests at an interval defined by
the`DRAGONFLY_LOAD_DURATION` environment variable. The jobs returned by the API
endpoint will then be spawned as tasks in the threadpool. This process repeats for
the duration of the program.

The client starts up by first authenticating with Auth0 to obtain an access
token. It then stores this access token in a shared-state thread
synchronization primitive that allows multiple concurrent readers but only one
writer. This new access token is used to fetch the YARA rules from the
Dragonfly API. The source code of the YARA rules is compiled (very much like
compiling regex) and stored in the shared state. Then, the necessary threads
are spawned. Once the threadpool task has finished scanning, it will send
it's results over the Dragonfly HTTP API.

### Environment variables

Below are a list of environment variables that need to be configured, and what
they do

<!-- markdownlint-disable MD013 -->
| Variable                  | Default                          | Description                                                                     |
| ------------------------- | -------------------------------- | ------------------------------------------------------------------------------- |
| `DRAGONFLY_BASE_URL`      | `https://dragonfly.vipyrsec.com` | The base API URL for the mainframe server                                       |
| `DRAGONFLY_AUTH0_DOMAIN`  | `vipyrsec.us.auth0.com`          | The auth0 domain that requests go to                                            |
| `DRAGONFLY_AUDIENCE`      | `https://dragonfly.vipyrsec.com` | Auth0 Audience field                                                            |
| `DRAGONFLY_CLIENT_ID`     |                                  | Auth0 client ID                                                                 |
| `DRAGONFLY_CLIENT_SECRET` |                                  | Auth0 client secret                                                             |
| `DRAGONFLY_USERNAME`      |                                  | Provisioned username                                                            |
| `DRAGONFLY_PASSWORD`      |                                  | Provisioned password                                                            |
| `DRAGONFLY_THREADS`       | Available parallelism / `1`      | Attempts to auto-detect the amount of threads, or defaults to 1 if not possible |
| `DRAGONFLY_LOAD_DURATION` | 60                               | Seconds to wait between each API job request                                    |
| `DRAGONFLY_BULK_SIZE`     | 20                               | The amount of jobs to request at once                                           |
<!-- markdownlint-enable MD013 -->
