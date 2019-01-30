# domain

[![Travis Build Status](https://travis-ci.org/NLnetLabs/domain-core.svg?branch=master)](https://travis-ci.org/NLnetLabs/domain-core)
[![AppVeyor Build
Status](https://ci.appveyor.com/api/projects/status/github/NLnetLabs/domain-core?svg=true)](https://ci.appveyor.com/project/partim/domain-core)

A family of crates (eventually) providing a comprehensive DNS library for
Rust. Currently, it consists of the following individual crates:

* [domain-core], containing the core data structures and functionality for
  handling DNS data,
* [domain-resolv], an asynchronous stub resolver.

All of these crates can be imported at once via the [domain] meta crate.

Additional crates will eventually provide functionality for authoritative
name servers, recursive resolvers, and more.

[domain]: https://github.com/NLnetLabs/domain-core/tree/master/domain
[domain-core]: https://github.com/NLnetLabs/domain-core/tree/master/domain-core
[domain-resolv]: https://github.com/NLnetLabs/domain-core/tree/master/domain-resolv

