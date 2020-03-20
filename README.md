# domain

[![Travis Build Status](https://travis-ci.org/NLnetLabs/domain-core.svg?branch=master)](https://travis-ci.org/NLnetLabs/domain-core)
[![AppVeyor Build
Status](https://ci.appveyor.com/api/projects/status/github/NLnetLabs/domain-core?svg=true)](https://ci.appveyor.com/project/partim/domain-core)

# Branch series-0.5

This branch tracks the changes for the upcoming 0.5 release of the domain
crate until they are stable enough for users to start migrating their
code.

The following tasks need to be done in order to reach that state:

* [x] Make core DNS types generic over octets sequences.
* [x] Restructure to use features instead of sub-crates.
* [x] Add changes from #38.
* [ ] Migrate to async/await and tokio 0.2.
* [ ] Update documentation.


# Original README.

A family of crates (eventually) providing a comprehensive DNS library for
Rust. Currently, it consists of the following individual crates:

* [domain-core], containing the core data structures and functionality for
  handling DNS data.

  [![Current](https://img.shields.io/crates/v/domain-core.svg)](https://crates.io/crates/domain-core)
  [![Documentation](https://docs.rs/domain-core/badge.svg)](https://docs.rs/domain-core)

* [domain-resolv], an asynchronous stub resolver.

  [![Current](https://img.shields.io/crates/v/domain-resolv.svg)](https://crates.io/crates/domain-resolv)
  [![Documentation](https://docs.rs/domain-resolv/badge.svg)](https://docs.rs/domain-resolv)

* [domain], a meta-crate providing access to all of the above.

  [![Current](https://img.shields.io/crates/v/domain.svg)](https://crates.io/crates/domain)
  [![Documentation](https://docs.rs/domain/badge.svg)](https://docs.rs/domain)


Additional crates will eventually provide functionality for authoritative
name servers, recursive resolvers, and more.

[domain]: https://github.com/NLnetLabs/domain-core/tree/master/domain
[domain-core]: https://github.com/NLnetLabs/domain-core/tree/master/domain-core
[domain-resolv]: https://github.com/NLnetLabs/domain-core/tree/master/domain-resolv


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

