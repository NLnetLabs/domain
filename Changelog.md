# Change Log

## Unreleased future version

Breaking Changes

* The generic octets foundation has been moved to a new crate *[octseq]*
  and completely revamped with Generic Associated Types stabilized in Rust
  1.65. This required changes all over the code but, hopefully, should
  result in relatively few changes when using the crate. ([#160])
* The range, slice, and split methods on the domain name types have changed.
  They have been merge into a single method taking ranges – except for those
  on `Dname` that require type changes. The split methods now take references
  and don’t change `self` anymore. ([#160])
* The `Parse`, `Compose`, and `Scan` traits have been demoted to mere
  extension traits for foreign types (primarily the built-in integers, so that
  you can do things like `u16::parse`). All other types now simply have
  methods matching the patterns. Where generics are necessary, dedicated
  traits have been added. E.g., there now are `ParseRecordData` and
  `ComposeRecordData` traits that are implemented by all record data types.
  ([#160])
* Various functions and methods of the `tsig` module now expect the
  current time as an argument to allow use of the module in a no-std
  environment. ([#152])
* Parsing of representation format and zonefiles has been completely
  re-written. ([#142], based on work in [#109] by [Martin Fischer])

New

* `Display` impls are now available for all EDNS0 options. ([#157])

Bug Fixes

Other Changes

[#109]: https://github.com/NLnetLabs/domain/pull/109
[#142]: https://github.com/NLnetLabs/domain/pull/142
[#152]: https://github.com/NLnetLabs/domain/pull/152
[#157]: https://github.com/NLnetLabs/domain/pull/157
[#160]: https://github.com/NLnetLabs/domain/pull/160
[Martin Fischer]: https://push-f.com/
[octseq]: https://crates.io/crates/octseq


## 0.7.1

Released 2022-10-06.

New

* Added a method `flatten_into` to record data types that  converts a
  value with a parsed (and thus possibly compressed) domain name into a one
  with a normal domain name. ([#151] by [@xofyarg])

Other Changes

* Disable default features for chrono. ([#149] by [@vavrusa])

[#149]: https://github.com/NLnetLabs/domain/pull/149
[#151]: https://github.com/NLnetLabs/domain/pull/151
[@vavrusa]: https://github.com/vavrusa
[@xofyarg]: https://github.com/xofyarg


## 0.7.0

Released 2022-09-15.

Breaking Changes

* The minimum supported Rust version is now 1.56.1. ([#128])
* The `OctetsBuilder` trait does not require `AsRef<[u8]>` and
  `AsMut<[u8]>` any more. These have been added as explicit trait bounds
  where needed. In return, `Cow<[u8]>` can now be used as an octets
  builder where `AsMut<[u8]>` is not needed. ([#130]).
* The `Display` implementation for `UncertainDname` now ends an absolute
  name with a dot to match the behaviour of the `FromStr` implementation.
  ([#116])
* The salt and hash parameters of `Nsec3` and `Nsec3Param` have been
  wrapped in newtypes. ([#116])
* Functions depending on the `rand` crate have been moved behind a new
  `random` feature as `rand` is not available on all systems, even with
  std support. The feature is, however, part of the default features.

  In particular, this means that `Header::set_random_id`,
  `MessageBuilder::request_axfr`, and `opt::rfc7830::PaddingMode::Random`
  are only available if the feature is enabled. ([#117] by @Jezza)
* `resolv::Resolver::Query` now has to be `Send`. This will allow the
  resolver to be used in async functions spawned onto a Tokio runtime.

  The stub resolver’s query struct is already Send, so no actual changes
  are necessary. However, because this changes the definition of the Resolver
  trait, this is a breaking change, anyway. ([#125])

New

* ``base::header::Flag` for easier working for the flags of a message
  header. ([#109] by [@tomaskrizek])
* `base::name::OwnedLabel` now implements `Clone` and `Copy` as well as
  `Display` and `Debug`. ([#112])
* `base::record::Record::into_owner_and_name` allows decomposing a record
  into its two parts that aren’t `Copy`. ([#114])
* Initial support for SVCB and HTTPS record types. ([#115] by [@xofyarg])
* Introduced Serde support for all relevant types. ([#116])
* The `OctetsBuilder` trait is now also implemented for mutable references
  of types that are octet builders and turn into themselves when frozen
  (i.e., `OctetsBuilder::Octets = Self`). ([#121])
* Support for [`heapless::Vec<u8, N>`] as an octets sequence via the new
  `heapless` feature. ([#122] by [@bugadani])
* The parameter types for SVCB record data now also implement `Eq`
  ([#135])

Bug Fixes

* Correctly encode and decode the address in EDNS client subnet when the
  number of bits isn’t divisible by 8. ([#101] and [#102] by [@xofyarg])
* `validate`:
  * Check for the correct public key size instead of infering if
    from the RRSIG length. ([#110] by [@vavrusa])
  * Canonalize the security algorithm before evaluation to avoid missing
    algorithm provided via the unknown integer variant. ([#127] by [@vavrusa])
* Support for no-std environments now actually works. ([#117] by @Jezza)
* Canonalize IANA types when scanning so that, e.g., `CLASS3` becomes
  `Class::Ch` instead of `Class::Int(3)`. ([#127] by [@vavrusa])
* `resolv`: Fixed generation of the domain name to be used for reverse
  IPv6 lookups. ([#131])

Other Changes

* Enable `doc_cfg` feature flag documentation for docs.rs.
  ([#104] by [Martin Fischer])

[#101]: https://github.com/NLnetLabs/domain/pull/101
[#102]: https://github.com/NLnetLabs/domain/pull/102
[#104]: https://github.com/NLnetLabs/domain/pull/104
[#109]: https://github.com/NLnetLabs/domain/pull/109
[#110]: https://github.com/NLnetLabs/domain/pull/110
[#112]: https://github.com/NLnetLabs/domain/pull/112
[#114]: https://github.com/NLnetLabs/domain/pull/114
[#115]: https://github.com/NLnetLabs/domain/pull/115
[#116]: https://github.com/NLnetLabs/domain/pull/116
[#117]: https://github.com/NLnetLabs/domain/pull/117
[#121]: https://github.com/NLnetLabs/domain/pull/121
[#122]: https://github.com/NLnetLabs/domain/pull/122
[#125]: https://github.com/NLnetLabs/domain/pull/125
[#127]: https://github.com/NLnetLabs/domain/pull/127
[#128]: https://github.com/NLnetLabs/domain/pull/128
[#130]: https://github.com/NLnetLabs/domain/pull/130
[#131]: https://github.com/NLnetLabs/domain/pull/131
[#135]: https://github.com/NLnetLabs/domain/pull/135
[@bugadani]: https://github.com/bugadani
[@Jezza]: https://github.com/Jezza
[@tomaskrizek]: https://github.com/tomaskrizek
[@vavrusa]: https://github.com/vavrusa
[@xofyarg]: https://github.com/xofyarg
[Martin Fischer]: https://push-f.com/


## 0.6.1

Released 2021-03-31.

This release is a maintenance release only in order to show the complete
documentation on docs.rs.

Other Changes

* Enables all features when building for doc.rs. ([#99])

[#99]: https://github.com/NLnetLabs/domain/pull/99


## 0.6.0

Released 2021-03-22.

Breaking

* The crate `domain-resolv` has been merged into this crate as the
  `domain::resolv` crate. It requires the `resolv` feature to be enabled.
  The `sync` feature from `domain-resolv` has been renamed to
  `resolv-sync`. ([#74])
* The trait `domain::base::octets::IntoOctets` has been merged into
  `domain::base::octets::OctetsBuilder`. It’s method `into_octets` is now
  available as `freeze` on `OctetsBuilder`. ([#75])
* Upgrade to tokio 1.0, bytes 1.0, and latest of other dependencies
  ([#84] by [@koivunej])

New

* Support for extended errors defined in [RFC 8914]. ([#79] by [@xofyarg])
* New traits `domain::base::octets::OctetsFrom` and `OctetsInto` to
  convert types that are generic over octets sequences between different
  octets sequences. ([#77])

Bug Fixes

* Fix domain name compressors when giving a root label only. ([#76]
  by [@vavrusa])
* Fix OptIter not skipping over other options correctly. ([#76]
  by [@vavrusa])
* Fix canonical comparison of TXT RDATA by taking the length labels into
  account. ([#76] by [@vavrusa])
* Fix parser not rejecting malformed TXT RDATA. ([#80] by [@vavrusa])
* Resolver: Host lookup now considers possibly separate CNAME chains for
  the responses to the A and AAAA queries. ([#90] by [@varusa])


Other Changes

[#74]: https://github.com/NLnetLabs/domain/pull/74
[#75]: https://github.com/NLnetLabs/domain/pull/75
[#76]: https://github.com/NLnetLabs/domain/pull/76
[#77]: https://github.com/NLnetLabs/domain/pull/77
[#79]: https://github.com/NLnetLabs/domain/pull/79
[#80]: https://github.com/NLnetLabs/domain/pull/80
[#84]: https://github.com/NLnetLabs/domain/pull/84
[#90]: https://github.com/NLnetLabs/domain/pull/90
[@vavrusa]: https://github.com/vavrusa
[@xofyarg]: https://github.com/xofyarg
[@koivunej]: https://github.com/koivunej
[RFC 8914]: https://tools.ietf.org/html/rfc8914


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

