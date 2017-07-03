# domain
A DNS library for Rust.

[![Travis Build Status](https://travis-ci.org/partim/domain.svg?branch=master)](https://travis-ci.org/partim/domain)
[![AppVeyor Build
Status](https://ci.appveyor.com/api/projects/status/github/partim/domain?svg=true)](https://ci.appveyor.com/project/partim/domain)
[![Current](https://img.shields.io/crates/v/domain.svg)](https://crates.io/crates/domain)

[Documentation](https://docs.rs/domain/)


## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
domain = "0.2"
```

Then, add this to your crate root:

```rust
extern crate domain;
```

*Note:* The resolver that is part of this crate only does DNS lookups. If
you want to perform lookups according to the system’s configuration,
including things such as looking at the local hosts file, consider using the
[netdb](https://github.com/partim/netdb) crate instead.


## Features (aka TODO)

Eventually, this crate will provide the following functions:

* [ ] DNS data handling
    
    * [X] Basic types.

    * [ ] Implementations for all IANA-registered record types.

    * [X] Wire-format parsing and constructing.

    * [ ] Master format parsing and constructing.

* [ ] Stub resolver.

    * [X] Asynchronous stub resolver based on
          [futures](https://github.com/alexcrichton/futures-rs) and
          [tokio](https://github.com/tokio-rs/tokio-core).
    
    * [ ] Rich set of DNS tasks:

        * [X] querying for raw DNS records,

        * [X] querying for host names,

        * [X] reverse host name queries,

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


## Help!

The stub resolver currently is of limited use under Windows since I have
no idea what the correct way to determine the system’s resolver
configuration is. I would be very grateful for a hint as to that, so the
crate becomes properly cross platform.


## Contributing

If you have comments, proposed changes, or would like to contribute,
please open an issue.


## Licensing

`domain` is distributed under the terms of the MIT license. See LICENSE
for details.
