# Tuning `dragonfly-client-rs`

Describes the configuration options in more detail.

## `DRAGONFLY_LOAD_DURATION`

Defaults to `60` seconds.

The time to wait between failed job requests, in seconds.

## `DRAGONFLY_MAX_SCAN_SIZE`
Defaults to `128_000_000` (128 MB).

The maximum size of downloaded distributions, in bytes. Setting this too high
may cause clients with low memory to run out of memory and crash, setting it
too low may mean most packages are not scanned (due to being above the size
limit).
