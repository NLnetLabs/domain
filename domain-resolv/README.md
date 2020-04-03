# A DNS library for Rust – Asynchronous Stub Resolver

[![Current](https://img.shields.io/crates/v/domain-resolv.svg)](https://crates.io/crates/domain-resolv)
[![Documentation](https://docs.rs/domain-resolv/badge.svg)](https://docs.rs/domain-resolv)

This crate provides a modern stub resolver using
[Tokio](https://tokio.rs/).

Please note that this crate will be merged as a module into the
[domain][https://crates.io/crates/domain] crate very soon.

## Features

Eventually, the stub resolver will provide the following functionality:

* [X] asynchronous stub resolver based on Tokio 0.1

    * [X] unencrypted connections via UDP and TCP,

    * [ ] encrypted connections via DNS-over-TLS,

    * [ ] encrypted connections via DNS-over-HTTP,

* [ ] rich set of queries:

    * [X] querying for raw DNS records,

    * [X] querying for IPv4 and IPv6 addresses,

        * [ ] priority according to ‘happy eyeballs,’

    * [X] querying for host names associated with IPv4 and IPv6 addresses,

    * [ ] querying for mail servers,

        * [ ] pure MX records,

        * [ ] IPv4 and IPv6 addresses of the mail server,

        * [ ] TLSA, SPF, DKIM, DMARC records,

    * [X] querying for servers via SRV records,

        * [X] pure SRV records,

        * [X] IPv4 and IPv6 addresses of the servers,

        * [ ] TLSA records of the servers,


## Contributing

If you have comments, proposed changes, or would like to contribute,
please open an issue.


## Licensing

`domain-resolv` is distributed under the terms of the BSD-3-clause license.
See LICENSE for details.


