# domain-rs
A DNS library for Rust.

[![Travis Build Status](https://travis-ci.org/cloudshipping/domain.svg?branch=master)](https://travis-ci.org/cloudshipping/domain)

## Usage

Since it is wildly incomplete, this crate is not yet on crates.io. If you
feel like using it anyway, add this to your `Cargo.toml`:

```toml
[dependencies]
domain-rs = { git = "https://github.com/cloudshipping/domain.git" }
```

Then, add this to your crate root:

```rust
extern crate domain;
```

## Features (aka TODO)

Eventually, this crate will provide the following functions:

* [ ] Types for DNS data.
    
    * [X] Basic types.
    * [ ] Implementations for all IANA-registered record type.

* [X] Wire-format parsing and constructing.

* [ ] Zonefile parsing and constructing.

* [ ] Stub resolver.

* [ ] Recursive resolver.

* [ ] Authoritative name server.

It will provide for the following DNS extensions and applications:

* [ ] NOTIFY and zone transfer.

* [ ] UPDATE.

* [ ] DNSSEC verification.

* [ ] DNSSEC signing.

* [ ] DANE.

* and probably more.
