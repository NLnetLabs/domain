# domain
A family of crates (eventually) providing a comprehensive DNS library for
Rust.

*NOTE: This repository will be renamed to https://github.com/NLnetLabs/domain
with the next release of domain-core.*

This repository contains the next iteration of the [domain] crate. It is
split over a number of crates providing specific parts of the DNS
experience. Currently, the following crates are published:

* [domain-core], containing the core data structures and functionality for
  handling DNS data.

The following additional crates are in development and will be released
soon:

* [domain-resolv], an asynchronous stub resolver.

Additional crates will eventually provide functionality for authoritative
name servers, recursive resolvers, and more.

[domain]: https://crates.io/crates/domain
[domain-core]: https://github.com/NLnetLabs/domain-core/tree/master/domain-core
[domain-resolv]: https://github.com/NLnetLabs/domain-core/tree/master/domain-resolv

