# domain – A DNS library for Rust

[![Current](https://img.shields.io/crates/v/domain.svg)](https://crates.io/crates/domain)
[![Documentation](https://docs.rs/domain/badge.svg)](https://docs.rs/domain)

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


## What’s Next?

We have collected our plans for the next steps in development of these
crates in the [Development Roadmap].

For ideas that would benefit from some user feedback, we are creating
issues with the [discuss] label.

If you have ideas, requests, or proposals, don’t hesitate to open issues.

[Development Roadmap]: https://github.com/NLnetLabs/domain/projects/1
[discuss]: https://github.com/NLnetLabs/domain/labels/discuss


## Contributing

If you have comments, proposed changes, or would like to contribute,
please open an issue.


## Licensing

All domain crates are distributed under the terms of the BSD-3-clause
license. See the LICENSE files in the individual crates for details.

