# domain-core
A DNS library for Rust – Core.

[![Travis Build Status](https://travis-ci.org/NLnetLabs/domain-core.svg?branch=master)](https://travis-ci.org/NLnetLabs/domain-core)
[![AppVeyor Build
Status](https://ci.appveyor.com/api/projects/status/github/NLnetLabs/domain-core?svg=true)](https://ci.appveyor.com/project/NLnetLabs/domain-core)
[![Current](https://img.shields.io/crates/v/domain-core.svg)](https://crates.io/crates/domain-core)

[Documentation](https://docs.rs/domain-core/)

This crate contains the core types and functionality for processing DNS
data. Resolvers, name servers, and more will be provided by additional
crates.


## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
domain-core = "0.3"
```

Then, add this to your crate root:

```rust
extern crate domain_core;
```


## Features (aka TODO)

Eventually, this crate will provide the following functions:

* [ ] DNS data handling
    
    * [X] Basic types.

    * [ ] Implementations for all IANA-registered record types.

    * [X] Wire-format parsing and constructing.

    * [ ] Master format parsing and constructing.

* [ ] DNSSEC signing

* [ ] DNSSEC validation


## Contributing

If you have comments, proposed changes, or would like to contribute,
please open an issue.


## Licensing

`domain-core` is distributed under the terms of the BSD-3-clause license.
See LICENSE for details.

