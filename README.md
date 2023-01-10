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
* support for signing and verifying messages using the TSIG mechanism,
* experimental support for reading data from DNS master files (also known
  as zone files),
* experimental and as yet incomplete support for DNSSEC signing and
  validation,
* a simple Tokio-based stub resolver.

If you have ideas, requests, or proposals for future features, pleased
don’t hesitate to open Github issues.


## Licensing

The domain crate is distributed under the terms of the BSD-3-clause
license. See the [LICENSE] file for details.

[LICENSE]: https://github.com/NLnetLabs/domain/blob/main/LICENSE

