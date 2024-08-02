# Overview

`dragonfly-client-rs` uses [Yara](https://virustotal.github.io/yara/) to scan
code pulled from the [Python Package Index](https://pypi.org/) (PYPI). It polls
for work from
[`dragonfly-mainframe`][1].

`dragonfly-client-rs` runs a main loop which does the following:

* Authenticate using OAuth2
* Fetch a job from [`dragonfly-mainframe`][1], which consists of a package to
  scan
* Scan the package
* Report the results

## Scanning

Packages are scanned using Yara.

## Reporting Results

An HTTP request is sent to [`dragonfly-mainframe`][1].

[1]: https://github.com/vipyrsec/dragonfly-mainframe
