# domain – A DNS library for Rust

[![Current](https://img.shields.io/crates/v/domain.svg)](https://crates.io/crates/domain)
[![Documentation](https://docs.rs/domain/badge.svg)](https://docs.rs/domain)
[![Mastodon Follow](https://img.shields.io/mastodon/follow/109262826617293067?domain=https%3A%2F%2Ffosstodon.org&style=social)](https://fosstodon.org/@nlnetlabs)

A library for interacting with the Domain Name System. The crate contains
an ever-growing set of building blocks for including DNS functionality in
applications.


Currently, these blocks include:

* basic data structures and functionality for creating and parsing DNS
  data and messages,
* a simple Tokio-based stub resolver,
* experimental support for DNS client and server transports,
* experimental support for reading data from DNS zone files, storing them
  in memory and answering queries,
* experimental support for zone transfer, including support for TSIG,
* experimental and as yet incomplete support for DNSSEC signing and
  validation.

The library is currently under
[heavy development](https://blog.nlnetlabs.nl/domain-foundations-the-first-of-our-five-year-vision/)
and additional building blocks and features are being added.


## Minimal Supported Rust Versions

We are trying to maintain a decent balance between being able to use older
compiler versions and using new features that improve safety and usability
of the crate.

### Minimum version: 1.68.2

The `rust-version` given in `Cargo.toml` is the oldest version that can
be used to compile the crate with the minimal versions of all dependencies
selected.

You can run `cargo +nightly update -Z minimal-versions` to ask Cargo to
select these minimal versions for all dependencies.

### Current version: 1.76.0

This is the minimum Rust version required to build with latest version of
all dependencies at time of release. `Cargo.lock` contains these versions
for reference.

## Licensing

The domain crate is distributed under the terms of the BSD-3-clause
license. See the [LICENSE] file for details.

[LICENSE]: https://github.com/NLnetLabs/domain/blob/main/LICENSE

