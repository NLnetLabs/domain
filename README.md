# domain
A DNS library for Rust.

[![Travis Build Status](https://travis-ci.org/cloudshipping/domain.svg?branch=master)](https://travis-ci.org/cloudshipping/domain)

## Usage

Since it is wildly incomplete, this crate is not yet on crates.io. If you
feel like using it anyway, add this to your `Cargo.toml`:

```toml
[dependencies]
domain = { git = "https://github.com/cloudshipping/domain.git" }
```

Then, add this to your crate root:

```rust
extern crate domain;
```

Please be aware that the crate is currently in a very early state and all
things can change without notice.


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


## Contributing

If you have comments, proposed changes, or would like to contribute,
please open an issue. Given that things are very early and in flux, a
PR without an issue first may or may not be a good idea. The current code
may lag behind the several changes of mind I’ve had in figuring out the
best way to do thing.

