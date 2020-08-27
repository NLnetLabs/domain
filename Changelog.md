# Change Log

## Unreleased 0.6.0

Breaking

* The crate `domain-resolv` has been merged into this crate as the
  `domain::resolv` crate. It requires the `resolv` feature to be enabled.
  The `sync` feature from `domain-resolv` has been renamed to
  `resolv-sync`. ([#74])
* The trait `domain::base::octets::IntoOctets` has been merged into
  `domain::base::octets::OctetsBuilder`. It’s method `into_octets` is now
  available as `freeze` on `OctetsBuilder. ([#75])

Bug Fixes

New

Other Changes

[#74]: https://github.com/NLnetLabs/domain/pull/74
[#75]: https://github.com/NLnetLabs/domain/pull/75


## 0.5.3

New

* `validate`: enable 1024 bit RSASHA512 as supported algorithm.
  ([#67], by [@vavrusa])

Bug Fixes

* Various minor fixes for building in no-std mode. ([#72])

[#67]: https://github.com/NLnetLabs/domain/pull/67
[#72]: https://github.com/NLnetLabs/domain/pull/72
[@vavrusa]: https://github.com/vavrusa


## 0.5.2

New

* Additional methods to manipulate an OPT record’s header in `OptBuilder`.
  ([#61], by [@vavrusa])

Dependencies

* Upgraded *ring* to 0.6.14 for fixes to 1024 bit RSASHA512. ([#62])

[#61]: https://github.com/NLnetLabs/domain/pull/61
[#62]: https://github.com/NLnetLabs/domain/pull/62
[@vavrusa]: https://github.com/vavrusa


## 0.5.1

New

* Support for the DNAME record type. ([#58], by [@vavrusa])

Bug Fixes

* Fix calculation of block lengths in `TxtBuilder`. ([#57], by [@vavrusa])
* Fix construction of options in OPT records. ([#59], by [@vavrusa])

[#57]: https://github.com/NLnetLabs/domain/pull/57
[#58]: https://github.com/NLnetLabs/domain/pull/58
[#59]: https://github.com/NLnetLabs/domain/pull/59
[@vavrusa]: https://github.com/vavrusa


## 0.5.0

This release contains a major restructuring and refactoring of the entire
library. The previous set of crates has been merged into a single crate
yet again with various modules being optional and available via features.


### Changes to former *domain-core*

The following notes list the changes relative to the *domain-core* crate.

Reorganization

* The modules in `domain_core::bits` have been moved to `domain::base`.
* The modules `domain_core::{iana, utils}` have been moved to
  `domain::base::{iana, utils}` respectively.
* Master file parsing and generation functionality is now only available
  if the feature `"master"` is enabled.

Breaking Changes

* All types that use octets sequences are now generic over the specific
  type of sequence. For details of the mechanism, please have a look at
  the documentation of the `base::octets` module.
* `rdata::rfc4035::Nsec` is now generic over the type of the next name.
  This is necessary because [RFC 6762] allows compression for its next name.
  ([#20], reported by Tom Pusateri)
* Removed the failure crate. All error types now impl `fmt::Display` and,
  if the `"std"` feature is enabled, `std::error::Error`. [(#33)]

New

* `base::message::Message::opt` returns a message’s OPT record if present.
  ([#6], thanks to Marek Vavruša!)
* unsafe `base::name::Dname::from_bytes_unchecked` in order to create
  names from well-known sequences. [(#31)]
* `compose::Compose::compose_canonical` for composing the canonical form
  for DNSSEC signing. It has a default implementation just doing `compose`
  and has been implemented for all relevant types. [(#XX)]
* `base::cmp::CanonicalOrd` for the ordering of record data and records for
  DNSSEC signing. Implemented for all relevant types. Also improved
  implementations of `PartialEq` and `PartialOrd` for types generic over
  domain name types to be generic over the other values domain name type.
* Allow `serial::Serial` to be created from datetimes, provide a
  constructor for `now` and add `sub`.
* Record data types for CDS and CDSKEY record types. (Provided by [@vendemiat]
  in [#24]).

Bug fixes

* Do not compress the target of an SRV record’s data. [(#18)]
* Fix multiple issues with `rdata::rfc4043`. ([#42] via [#38] by [@vavrusa])
* Fix multiple issues with `base::opt`. ([#42] via [#38] by [@vavrusa])
* Fixed infinite loops in `Message::canonical_name`. ([#42] via [#38] by
  [@vavrusa])

Dependencies

* The `std`, `bytes`, and `chrono` crates are now optional and can be enabled
  via features.


### New

* The new `sign` module provides DNSSEC signing. It is available if the
  `"sign"` feature is enabled.
* The new `tsig` module provides TSIG signing and validation. It is only
  available if the `"tsig"` feature is enabled.
* The new `validate` module provides functionality necessary for DNSSEC
  validation. It is only available if the `"validate"` feature is enabled.


[#6]: https://github.com/NLnetLabs/domain/pull/6
[(#14)]: https://github.com/NLnetLabs/domain/pull/14
[#20]: https://github.com/NLnetLabs/domain/pull/19
[#24]: https://github.com/NLnetLabs/domain/pull/24
[#26]: https://github.com/NLnetLabs/domain/pull/26
[(#31)]: https://github.com/NLnetLabs/domain/pull/31
[(#33)]: https://github.com/NLnetLabs/domain/pull/33
[#38]: https://github.com/NLnetLabs/domain/pull/38
[#42]: https://github.com/NLnetLabs/domain/pull/42
[@dvc94ch]: https://github.com/dvc94ch
[@vavrusa]: https://github.com/vavrusa
[@vendemiat]: https://github.com/vendemiat

