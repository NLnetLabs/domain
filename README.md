# domain
A DNS library for Rust.

[![Travis Build Status](https://travis-ci.org/partim/domain.svg?branch=master)](https://travis-ci.org/partim/domain)

[Documentation](https://partim.github.io/domain/domain/index.html)

## Usage

Since it is wildly incomplete, this crate is not yet on crates.io. If you
feel like using it anyway, add this to your `Cargo.toml`:

```toml
[dependencies]
domain = { git = "https://github.com/partim/domain.git" }
```

Then, add this to your crate root:

```rust
extern crate domain;
```

Please be aware that the crate is currently in a very early state and all
things can change without notice.


## Features (aka TODO)

Eventually, this crate will provide the following functions:

* [ ] DNS data handling
    
    * [X] Basic types.

    * [ ] Implementations for all IANA-registered record types.

    * [X] Wire-format parsing and constructing.

    * [ ] Zonefile parsing and constructing.

* [ ] Stub resolver.

    * [ ] Asynchronous stub resolver based on
          [futures](https://github.com/alexcrichton/futures-rs) and
          [tokio](https://github.com/tokio-rs/tokio-core).
    
    * [ ] Rich set of DNS tasks:

        * [ ] querying for raw DNS records,

        * [ ] querying for host names,

        * [ ] reverse host name queries,

        * [ ] querying for mail servers (MX records),

        * [ ] querying for server addresses based on SRV,

        * [ ] verification of server certificates based on TLSA,

        * [ ] verification of PGP keys based on OPENPGPKEY,

        * [ ] verification of S/MIME certificates based on SMIMEA,

    * [ ] EDNS support.

    * [ ] DNSSEC verification of records.

    * [ ] DTLS- and TLS-secured connections to upstream resolver.

* [ ] Recursive resolver (details TBD).

* [ ] Authoritative name server (details TBD).

The idea for both the recursive resolver and the authoritative name server
currently is to supply libraries that allow including this functionality
in programs instead of building general purpose products. We may split
the four top-level points into separate crates along the way.


## Contributing

If you have comments, proposed changes, or would like to contribute,
please open an issue. Given that things are very early and in flux, a
PR without an issue first may or may not be a good idea. The current code
may lag behind the several changes of mind I’ve had in figuring out the
best way to do things.

