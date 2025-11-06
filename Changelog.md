# Change Log

## Unreleased next version

Breaking changes

* Add new `LimitExceeded` variant to `MessageBuilder`'s `PushError`. ([#349])
* `StubResolver` now keeps its state in an `Arc` and can be cloned cheaply.
  ([#393])

New

* Add `rdata::dnssec::Timestamp::to_system_time` to help sorting timestamps.
 ([#548])

Improvements

* Exclude `moka` dependency from the `resolv` feature, reducing the number of
  dependencies and compile time significantly. ([#575] by [@WhyNotHugo])

Bug fixes

* When parsing a Bind-style public key file, allow an optional TTL field.
  ([#593])

Unstable features

* `unstable-crypto-sign`
  * Add support for RSA/SHA-512 to openssl signer. ([#550])
* `unstable-server-transport`
  * Implement `std::error::Error` for `ServiceError`. ([#570] by
    [@rossmacarthur])
  * Be more lenient when timing out connections while they are in a
    transaction. ([#399])
* `unstable-xfr`
  * Various fixes and improvements. ([#507])

Other changes

[#349]: https://github.com/NLnetLabs/domain/pull/349
[#393]: https://github.com/NLnetLabs/domain/pull/393
[#399]: https://github.com/NLnetLabs/domain/pull/399
[#507]: https://github.com/NLnetLabs/domain/pull/507
[#548]: https://github.com/NLnetLabs/domain/pull/548
[#550]: https://github.com/NLnetLabs/domain/pull/550
[#570]: https://github.com/NLnetLabs/domain/pull/570
[#593]: https://github.com/NLnetLabs/domain/pull/593
[@rossmacarthur]: https://github.com/rossmacarthur
[@WhyNotHugo]: https://github.com/WhyNotHugo


## 0.11.1

Released 2025-10-22.

Bug fixes

* Fix handling of tabs when formatting RDATA using `DisplayKind::Tabbed`.
  ([#516])
* Fix for in-place zone parser yielding incorrect TTLs. ([#538])
* Generalize `ZoneUpdater` to support any `Record` type, not just
  `ParsedRecord`. ([#535])
* Trim leading modulus and public exponent zeroes per RFC 3110 section 2.
  ([#541])
* Fix panic in zonetree from in-place zonefile after encountering a malformed
  record. ([#573])

Unstable features

* `unstable-server-transport`:
  * Don't discard the NOTIFY SOA serial, if one is received. Existing users
    of the `Notifiable` trait will need to update their code as this change
    adds an argument to `Notifiable::notify_zone_changed()`. [#562])
* `unstable-client-transport`:
  * Fix an issue in Stream::Transport when a reply arrives early.
    ([#568] by [@TheJokr])

Other changes

* Fix docs on `XfrResponseInterpreter`. ([#510])


[#510]: https://github.com/NLnetLabs/domain/pull/510
[#516]: https://github.com/NLnetLabs/domain/pull/516
[#535]: https://github.com/NLnetLabs/domain/pull/535
[#538]: https://github.com/NLnetLabs/domain/pull/538
[#541]: https://github.com/NLnetLabs/domain/pull/541
[#562]: https://github.com/NLnetLabs/domain/pull/562
[#568]: https://github.com/NLnetLabs/domain/pull/568
[#573]: https://github.com/NLnetLabs/domain/pull/573
[@TheJokr]: https://github.com/TheJokr


## 0.11.0

Released 2025-05-21.

Breaking changes

* FIX: Use base 16 per RFC 4034 for the DS digest, not base 64. ([#423])
* FIX: NSEC3 salt strings should only be accepted if within the salt size limit. (#431)
* Stricter RFC 1035 compliance by default in the `Zonefile` parser. ([#477])
* Rename {DigestAlg, Nsec3HashAlg, SecAlg, ZonemdAlg} to
  {DigestAlgorithm, Nsec3HashAlgorithm, SecurityAlgorithm, ZonemdAlgorithm}

New

* Added `HashCompressor`, an unlimited name compressor that uses a hash map
  rather than a tree. ([#396])
* Changed `fmt::Display` for `HINFO` records to a show a quoted string.
  ([#421])
* Added support for `NAPTR` record type. ([#427] by [@weilence])
* Added initial fuzz testing support for some types via a new `arbitrary`
  feature (not enabled by default). ([#441])
* Added `StubResolver::add_connection()` to allow adding a connection to the
  running resolver. In combination with `ResolvConf::new()` this can also be
  used to control the connections made when testing code that uses the stub
  resolver. ([#440])
* Added `ZonefileFmt` trait for printing records as zonefiles. ([#379], [#446],
  [#463])

Bug fixes

* NSEC records should include themselves in the generated bitmap. ([#417])
* Trailing double quote wrongly preserved when parsing record data. ([#470],
  [#472])
* Don't error with unexpected end of entry for RFC 3597 RDATA of length zero. ([475])

Unstable features

* New unstable feature `unstable-crypto` that enable cryptography support
  for features that do not rely on secret keys. This feature needs either
  or both of the features `ring` and `openssl` ([#416])
* New unstable feature `unstable-crypto-sign` that enable cryptography support
  including features that rely on secret keys. This feature needs either
  or both of the features `ring` and `openssl` ([#416])
* New unstable feature `unstable-client-cache` that enable the client transport
  cache. The reason is that the client cache uses the `moka` crate.

* New unstable feature `unstable-new` that introduces a new API for all of
  domain (currently only with `base`, `rdata`, and `edns` modules).  Also see
  the [associated blog post][new-base-post].

* `unstable-server-transport`
  * The trait `SingleService` which is a simplified service trait for
    requests that should generate a single response ([#353]).
  * The trait `ComposeReply` and an implementation of the trait
    (`ReplyMessage`) to assist in capturing EDNS(0) options that should be
    included in a response message ([#353]).
  * Adapters to implement `Service` for `SingleService` and to implement
    `SingleService` for `SendRequest` ([#353]).
  * Conversion of a `Request` to a `RequestMessage` ([#353]).
  * A sample query router, called `QnameRouter`, that routes requests based
    on the QNAME field in the request ([#353]).

* `unstable-client-transport`
  * introduce timeout option in multi_stream ([#424]).
  * improve probing in redundant ([#424]).
  * restructure configuration for multi_stream and redundant ([#424]).
  * introduce a load balancer client transport. This transport tries to
    distribute requests equally over upstream transports ([#425]).
  * the client cache now has it's own feature `unstable-client-cache`.

* `unstable-sign`
  * add key lifecycle management ([#459]).
  * add support for adding NSEC3 records when signing.
  * add support for ZONEMD.

* `unstable-validator`
  * The `validate` crate is moved to `dnssec::validator::base`.
  * The `validator` crate is moved to `dnssec::validator`.

Other changes

[#353]: https://github.com/NLnetLabs/domain/pull/353
[#379]: https://github.com/NLnetLabs/domain/pull/379
[#396]: https://github.com/NLnetLabs/domain/pull/396
[#416]: https://github.com/NLnetLabs/domain/pull/416
[#417]: https://github.com/NLnetLabs/domain/pull/417
[#421]: https://github.com/NLnetLabs/domain/pull/421
[#423]: https://github.com/NLnetLabs/domain/pull/423
[#424]: https://github.com/NLnetLabs/domain/pull/424
[#425]: https://github.com/NLnetLabs/domain/pull/425
[#427]: https://github.com/NLnetLabs/domain/pull/427
[#431]: https://github.com/NLnetLabs/domain/pull/431
[#440]: https://github.com/NLnetLabs/domain/pull/440
[#441]: https://github.com/NLnetLabs/domain/pull/441
[#446]: https://github.com/NLnetLabs/domain/pull/446
[#459]: https://github.com/NLnetLabs/domain/pull/459
[#463]: https://github.com/NLnetLabs/domain/pull/463
[#470]: https://github.com/NLnetLabs/domain/pull/470
[#472]: https://github.com/NLnetLabs/domain/pull/472
[#474]: https://github.com/NLnetLabs/domain/pull/474
[#475]: https://github.com/NLnetLabs/domain/pull/475
[#477]: https://github.com/NLnetLabs/domain/pull/477
[@weilence]: https://github.com/weilence
[new-base-post]: https://blog.nlnetlabs.nl/overhauling-domain/


## 0.10.4

Released 2025-03-31.

Other changes

* Fix a build issue with [*time*](https://time-rs.github.io/) 0.3.41.
  ([#505], backported from [#503] by [@PSeitz])

[#503]: https://github.com/NLnetLabs/domain/pull/503
[#505]: https://github.com/NLnetLabs/domain/pull/505
[@PSeitz]: https://github.com/PSeitz


## 0.10.3

Released 2024-10-14.

New

* Added `Deserialize` impl for the `base::net::nostd::Ipv6Addr` and fixed
  the impl for `Ipv4Addr`. ([#413])

Bug fixes

* Fixed an incorrect feature gate that blocks compilation if only `"net"`
  is enabled. ([#412])
* Added (all? most?) missing feature dependencies for all features.
* Fixed `Deserialize` impls for `ParsedName` and `ExtendedError` to compile
  and work without `std`. ([#413])

[#412]: https://github.com/NLnetLabs/domain/pull/412
[#413]: https://github.com/NLnetLabs/domain/pull/413


## 0.10.2

Released 2024-10-10.

New

* Added an optional push size limit to `MessageBuilder`. ([#348])
* Added `FromStr` impls for `Rcode` and `OptRcode`. ([#357])
* Added `OptRcode::is_ext` to check if the code is an extended code.
  ([#358])
* Added `Rtype::is_glue` to check if the Rtype may be used as glue. ([#363])
* Added `MessageBuilder::start_error`, like `start_answer` but infallible. ([#369])
* Added `AnswerBuilder::push_ref`, like `push` but takes the record by
  reference. ([#383])
* Added `Rtype::NXNAME` and `ExtendedErrorCode::INVALID_QUERY_TYPE`. ([#392])
* Added a `Serialize` impl to `AllRecordData` and as a consequence to
  the OPT record and all OPT options, as well as `ParsedName`. ([#343])
* Added `Display` impl to `tsig::Key`. ([#397])

Bug fixes

* Fixed a mistake in the tsig module while calculating the start of
  the TSIG record when there were other records in the additional section,
  causing the TSIG code to fail if OPT records were in use. ([#333])
* Fixed the mnemonic for the `NOTAUTH` rcode – it was `NOAUTH`. ([#360])
* Fixed the way the `Txt<_> `record data implements comparison-related
  traits. They now directly compare the underlying octets, i.e., the wire
  format bytes. ([#374] by [@dklbreitling])
* Fixed the `tsig` module to reject messages with multiple TSIG records.
  ([#334])
* Fixed Display rendering of empty NSEC3 salt to be '-' per RFC 5155
  section 3.3. ([#407])

Unstable features

* New unstable feature `unstable-validator` that adds a DNSSEC validator.
  ([#328])
* New unstable feature `unstable-xfr` that adds `XfrResponseInterpreter` for
  iterating over XFR responses as a sequence of high level `ZoneUpdate`s, and
  `XfrMiddlewareSvc` and `XfrDataProvider` for responding to received XFR
  requests. ([#375], [#384])
* `unstable-client-transport`:
  * Fixed an issue with slow responses in the
    `multi_stream` transport by not waiting in the first iteration if an
    underlying stream reports its connection being closed. ([#338])
  * Added an option called `idle_timeout` to stream that allows a TCP or
    TLS connection to stay open even if no TcpKeepalive option is received
    from the server. ([#341])
  * Fixed an off-by-one error in Dgram client retry count checking. ([#354])
  * Added support for requests that may result in multiple responses. This
    adds `ComposeRequestMulti` and other `*Multi` types. The main change is to
    the stream transport, which is the only transport that implements
    `SendRequestMulti`. ([#377])
  * Added a TSIG request signing and response validating passthrough
    transport in `net::client:tsig`. ([#373])
* `unstable-server-transport`
  * Breaking changes to the `Service` and middleware traits. ([#369])
  * Added `TsigMiddlewareSvc` request validating and response signing
    middleware in `net::server::middleware::tsig`. ([#380])
  * Added `NotifyMiddlewareSvc` in `net::server::middleware::notify` to parse
    and acknowledge SOA NOTIFY requests, for use by secondary nameservers to
    detect outdated zones compared to the primary. ([#382])
  * `CookiesMiddlewareSvc` now allows requests with invalid cookies to proceed
    if they are authenticated or not required to authenticate. ([#336])
  * Added an `enabled` flag to `CookiesMiddlewareSvc`. ([#369])
  * Added trait `ResourceRecordBatcher` and impl `CallbackBatcher` in
    `net::server::batcher` for pushing as many records into a response as will
    fit according to defined limits. ([#383])
  * Enforce dgram max response size limit. ([#398])
  * Extended MandatoryMiddlewareSvc with an RFC 9619 check for opcode QUERY
    with QDCOUNT > 1. ([#365])
  * Added blanket `SendRequest` and `SendRequestMulti` impls for boxes. ([#397])
  * `EdnsMiddlewareSvc` fixes: ([#355])
    * Reply with FORMERR if an OPT RR cannot be parsed.
    * Don't reply with FORMERR if an edns-tcp-keepalive option is received via
      UDP, instead ignore it per RFC 7828 3.2.1.
    * Only reserve space for an edns-tcp-keepalive option for TCP requests,
      not UDP requests.
    * Always reserve space for an OPT RR in the response for any request that
      has an OPT RR, not just TCP requests.
  * Servers now drop received DNS response messages. ([#381])
  * Improved handling of errors while sending TCP responses. ([#309])
  * Correctly reserve space for OPT in `EdnsMiddlewareSvc`. ([#403])
* `unstable-zonetree`:
  * Added `ZoneUpdate`. ([#375])
  * Added `ZoneUpdater`, `ZoneDiff`, `InMemoryZoneDiffBuilder`,
    `InMemoryZoneDiff` and improved `ZoneUpdate`. ([#376], [#384])
  * Improved zonefile parsing error messages. ([#362]). 
  * `TryFrom<inplace::Zonefile> for Zonefile` now returns the set of
    errors instead of logging and ignoring them. ([#362])
  * Allow both glue (A/AAAA) and zone cuts at the same owner when zone
    parsing. ([#363])
  * Altered the logic in `Versioned::remove_all()` (formerly
    `Versioned::clean()`) as it made destructive changes to the zone that
    would have impacted readers of the current zone version while the new zone
    version was being created. ([#376])
  * Removed / renamed references to `clean` in `zonetree::in_memory` to
    `remove`. ([#376])
  * Fixed zone walking to include non-leaf CNAMEs. ([#352])
  * Fixed zone walking to pass the correct owner name to the callback.
    ([#384])
  * Added an `as_any` method and `Clone` and `Debug` impls to various zonetree
    types. ([#397])
  * Added `AsRef<dyn ZoneStore>` to `Zone`. ([#397])
  * Added handling of the AA flag and additional records to answer generation.
    ([#400])
  * Zone walking now includes glue records. A new flag `at_zone_cut` was
    added to the callback interface. ([#401])

[#309]: https://github.com/NLnetLabs/domain/pull/309
[#328]: https://github.com/NLnetLabs/domain/pull/328
[#333]: https://github.com/NLnetLabs/domain/pull/333
[#334]: https://github.com/NLnetLabs/domain/pull/334
[#336]: https://github.com/NLnetLabs/domain/pull/336
[#338]: https://github.com/NLnetLabs/domain/pull/338
[#341]: https://github.com/NLnetLabs/domain/pull/341
[#343]: https://github.com/NLnetLabs/domain/pull/343
[#348]: https://github.com/NLnetLabs/domain/pull/348
[#352]: https://github.com/NLnetLabs/domain/pull/352
[#354]: https://github.com/NLnetLabs/domain/pull/354
[#355]: https://github.com/NLnetLabs/domain/pull/355
[#357]: https://github.com/NLnetLabs/domain/pull/357
[#358]: https://github.com/NLnetLabs/domain/pull/358
[#360]: https://github.com/NLnetLabs/domain/pull/360
[#362]: https://github.com/NLnetLabs/domain/pull/362
[#363]: https://github.com/NLnetLabs/domain/pull/363
[#365]: https://github.com/NLnetLabs/domain/pull/365
[#369]: https://github.com/NLnetLabs/domain/pull/369
[#373]: https://github.com/NLnetLabs/domain/pull/373
[#374]: https://github.com/NLnetLabs/domain/pull/374
[#375]: https://github.com/NLnetLabs/domain/pull/375
[#376]: https://github.com/NLnetLabs/domain/pull/376
[#377]: https://github.com/NLnetLabs/domain/pull/377
[#380]: https://github.com/NLnetLabs/domain/pull/380
[#381]: https://github.com/NLnetLabs/domain/pull/381
[#382]: https://github.com/NLnetLabs/domain/pull/382
[#383]: https://github.com/NLnetLabs/domain/pull/383
[#384]: https://github.com/NLnetLabs/domain/pull/384
[#392]: https://github.com/NLnetLabs/domain/pull/392
[#397]: https://github.com/NLnetLabs/domain/pull/397
[#398]: https://github.com/NLnetLabs/domain/pull/398
[#400]: https://github.com/NLnetLabs/domain/pull/400
[#401]: https://github.com/NLnetLabs/domain/pull/401
[#403]: https://github.com/NLnetLabs/domain/pull/403
[#407]: https://github.com/NLnetLabs/domain/pull/407
[@dklbreitling]: https://github.com/dklbreitling


## 0.10.1

Release 2024-06-03.

New

* Allow AllRecordData’s parsing impls to accept an unsized [u8] as the
  source octets. ([#310] by [@xofyarg])
* Made `sign::records::FamilyName` public. ([#312] by [@achow101])
* Added an impl of `FromStr` for `Question`. ([#317])

Bug fixes

* Accept an empty record type bitmap when scanning NSEC/NSEC3 data.
  ([#310] by [@xofyarg])
* Fix serialization of ProtoRrsig to conform with RFC 4034. ([#313 by
  [@achow101])
* Add `?Sized` bounds to `Message::is_answer` and `ParsedRecord::to_record`.
  ([#318] by [@xofyarg], [#325] by [@hunts])
* Bring back `MessageBuilder::as_target`. ([#318] by [@xofyarg])
* Bring back `impl FreezeBuilder for StaticCompressor`. ([#318] by [@xofyarg])
* `sign::records::RecordsIter::skip_before` now stops at the first name in
  zone even if the apex itself doesn’t appear. ([#314] by [@achow101])
* Fix a counting error in `SliceLabelsIter::next` that broke compression
  via `StaticCompressor`. ([#321] by [@hunts])

Unstable features

* New unstable feature `unstable-stelline` for the Stelline testing
  framework as a “normal” module of _domain._ ([#315])
* `unstable-server-transport`:
  *  Redesigned the service trait and changes middleware processors as
     services that take an upstream service to pass requests on to. ([#307])
* `unstable-zonetree`:
  * Renamed the domain name types in `zonetree` from `Dname` to `Name`.
    ([#308])

Other changes

* The minimum Rust version is now 1.78. ([#320])

[#307]: https://github.com/NLnetLabs/domain/pull/307
[#308]: https://github.com/NLnetLabs/domain/pull/308
[#310]: https://github.com/NLnetLabs/domain/pull/310
[#312]: https://github.com/NLnetLabs/domain/pull/312
[#314]: https://github.com/NLnetLabs/domain/pull/314
[#315]: https://github.com/NLnetLabs/domain/pull/315
[#317]: https://github.com/NLnetLabs/domain/pull/317
[#318]: https://github.com/NLnetLabs/domain/pull/318
[#320]: https://github.com/NLnetLabs/domain/pull/320
[#321]: https://github.com/NLnetLabs/domain/pull/321
[#325]: https://github.com/NLnetLabs/domain/pull/325
[@achow101]: https://github.com/achow101
[@hunts]: https://github.com/hunts
[@xofyarg]: https://github.com/xofyarg

## 0.10.0

Released 2024-04-30.

Breaking changes

* All types and functions referring to domain names have been changed from
  using the term “dname” to just “name.” For instance, `Dname` has become
  `Name`, `ToDname` has become `ToName`, and `ToDname::to_dname` has become
  `ToName::to_name`. ([#290])
* The `ToName` and `ToRelativeName` traits have been changed to have a
  pair of methods a la `try_to_name` and `to_name` for octets builders
  with limited and unlimited buffers, reflecting the pattern used
  elsewhere. ([#285])
* The types for IANA-registered parameters in `base::iana` have been
  changed from enums to a newtypes around their underlying integer type
  and associated constants for the registered values. (This was really
  always the better way to structure this.) ([#276], [#298])
* The `Txt` record data type now rejects empty record data as invalid. As
  a consequence `TxtBuilder` converts an empty builder into TXT record
  data consisting of one empty character string which requires
  `TxtBuilder::finish` to be able to return an error. ([#267])
* `Txt` record data serialization has been redesigned. It now serialized as
  a sequence of character strings. It also deserializes from such a sequence.
  If supported by the format, it alternatively deserializes from a string that
  is broken up into 255 octet chunks if necessary. ([#268])
* The text formatting for `CharStr` has been redesigned. The `Display`
  impl now uses a modified version of the representation format that
  doesn’t escape white space but also doesn’t enclose the string in
  quotes. Methods for explicitly formatting in quoted and unquoted
  presentation format are provided. ([#270])
* The `validate::RrsigExt` trait now accepts anything that impls
  `AsRef<Record<..>>` to allow the use of smart pointers. ([#288] by
  [@hunts])
* The stub resolver now uses the new client transports. This doesn’t change
  how it is used but does change how it queries the configured servers.
  ([#215])
* The sub resolver’s server configuration `Transport` type has been
  changed to be either `Transport::UdpTcp` for trying UDP and if that
  leads to a truncated answer try TCP and `Transport::Tcp` for only trying
  TCP. The stub resolver uses these accordingly now ([#296])
* Many error types have been changed from enums to structs that hide
  internal error details. Enums have been kept for errors where
  distinguishing variants might be meaningful for dealing with the error.
  ([#277])
* Renamed `Dnskey::is_zsk` to `is_zone_key`. ([#292])
* Split RRSIG timestamp handling from `Serial` into a new type
  `rdata::dnssec::Timestamp`. ([#294])
* Upgraded `octseq` to 0.5. ([#257])
* The minimum Rust version is now 1.70. ([#304])

New

* Add impls for `AsRef<RelativeDname<[u8]>>` and `Borrow<RelativeDname<[u8]>>`
  to `RelativeDname<_>`. ([#251] by [@torin-carey])
* Added `name::Chain::fmt_with_dots` to format an absolute chained name
  with a final dot. ([#253])
* Added a new `ParseAnyRecordData` trait for record data types that can
  parse any type of record data. ([#256])
* Added implementations of `OctetsFrom` and `Debug` to `AllOptData` and
  the specific options types that didn’t have them yet. ([#257])
* Added missing ordering impls to `ZoneRecordData`, `AllRecordData`,
  `Opt`, and `SvcbRdata`. ([#293])
* Added `Name::reverse_from_addr` that creates a domain name for the
  reverse lookup of an IP address. ([#289])
* Added `OptBuilder::clone_from` to replace the OPT record with the
  content of another OPT record. ([#299])
* Added `Message::for_slice_ref` that returns a `Message<&[u8]>`. ([#300])

Bug fixes

* Fixed the display implementation of `name::Chain<_, _>`. ([#253])
* Fixed the display implementation of `rdata::Txt<..>`. It now displays
  each embedded character string separately in quoted form. ([#259])
* Fixed the extended part returned by `OptRcode::to_parts` (it was shifted
  by 4 bits too many) and return all 12 bits for the `Int` variant in
  `OptRcode::to_int`. ([#258])
* Fixed a bug in the `inplace` zonefile parser that made it reject
  character string of length 255. ([#284])

Unstable features

* Added the module `net::client` with experimental support for client
  message transport, i.e., sending of requests and receiving responses
  as well as caching of responses.
  This is gated by the `unstable-client-transport` feature. ([#215],[#275])
* Added the module `net::server` with experimental support for server
  transports, processing requests through a middleware chain and a service
  trait.
  This is gated by the `unstable-server-transport` feature. ([#274])
* Added the module `zonetree` providing basic traits representing a
  collection of zones and their data. The `zonetree::in_memory` module 
  provides an in-memory implementation. The `zonetree::parsed` module
  provides a way to classify RRsets before inserting them into a tree.
  This is gated by the `unstable-zonetree` feature. ([#286])


[#215]: https://github.com/NLnetLabs/domain/pull/215
[#251]: https://github.com/NLnetLabs/domain/pull/251
[#253]: https://github.com/NLnetLabs/domain/pull/253
[#256]: https://github.com/NLnetLabs/domain/pull/256
[#257]: https://github.com/NLnetLabs/domain/pull/257
[#258]: https://github.com/NLnetLabs/domain/pull/258
[#259]: https://github.com/NLnetLabs/domain/pull/259
[#267]: https://github.com/NLnetLabs/domain/pull/267
[#268]: https://github.com/NLnetLabs/domain/pull/268
[#270]: https://github.com/NLnetLabs/domain/pull/270
[#274]: https://github.com/NLnetLabs/domain/pull/274
[#275]: https://github.com/NLnetLabs/domain/pull/275
[#276]: https://github.com/NLnetLabs/domain/pull/276
[#277]: https://github.com/NLnetLabs/domain/pull/277
[#284]: https://github.com/NLnetLabs/domain/pull/284
[#285]: https://github.com/NLnetLabs/domain/pull/285
[#286]: https://github.com/NLnetLabs/domain/pull/286
[#288]: https://github.com/NLnetLabs/domain/pull/288
[#289]: https://github.com/NLnetLabs/domain/pull/289
[#290]: https://github.com/NLnetLabs/domain/pull/290
[#292]: https://github.com/NLnetLabs/domain/pull/292
[#293]: https://github.com/NLnetLabs/domain/pull/293
[#296]: https://github.com/NLnetLabs/domain/pull/296
[#298]: https://github.com/NLnetLabs/domain/pull/298
[#299]: https://github.com/NLnetLabs/domain/pull/299
[#300]: https://github.com/NLnetLabs/domain/pull/300
[#304]: https://github.com/NLnetLabs/domain/pull/304
[@torin-carey]: https://github.com/torin-carey
[@hunts]: https://github.com/hunts


## 0.9.3

Released 2023-12-29.

Bug fixes

* Fixed various issues preventing building in a no-std environment.
  ([#247] by [@dzamlo], [#248] by [@reitermarkus])

Other changes

* The `resolv` feature now depends on `futures_util` instead of `futures`,
  trimming unused dependencies from the dependency tree. ([#246] by
  [@WhyNotHugo])

[#246]: https://github.com/NLnetLabs/domain/pull/246
[#247]: https://github.com/NLnetLabs/domain/pull/246
[#248]: https://github.com/NLnetLabs/domain/pull/246
[@dzamlo]: https://github.com/dzamlo
[@reitermarkus]: https://github.com/reitermarkus
[@WhyNotHugo]: https://github.com/WhyNotHugo


## 0.9.2

Released 2023-11-16.

New

* Removed the `Sized` bound for octets types used by the `tsig` module.
  ([#241] by [@torin-carey])
* Added an impl for `AsRef<Message<[u8]>>` for any message. ([#242] by
  [@torin-carey])

Bug fixes

* Fixed in scanning absolute domain names from a zonefile that resulted
  in illegal wire data being produced. ([#240] by [@xofyarg)]

[#240]: https://github.com/NLnetLabs/domain/pull/240
[#241]: https://github.com/NLnetLabs/domain/pull/241
[#242]: https://github.com/NLnetLabs/domain/pull/242
[@torin-carey]: https://github.com/torin-carey
[@xofyarg]: https://github.com/xofyarg


## 0.9.1

Released 2023-10-27.

Bug fixes

* Added missing `?Sized` bounds to the octets type for parsing
  `ZoneRecordData` and `UnknownRecordData`. ([#237] by [@hunts])

[#237]: https://github.com/NLnetLabs/domain/pull/237
[@hunts]: https://github.com/hunts


## 0.9.0

Released 2023-09-18.

Breaking changes

* Move the `flatten_into` method for converting domain names into a
  straight, flat form into a new `FlattenInto` trait. This trait is only
  implemented for types that actually are or contain domain names. ([#216])
* Marked various methods and functions that return values without side
  effects as `#[must_use]`. ([#228] by [@WhyNotHugo])
* Changed the signature of `FoundSrvs::merge` to use a non-mut `other`.
  ([#232])
* The minimum Rust version is now 1.67. ([#235])

New

* Added support for the ZONEMD record type. ([#229] by [@xofyarg])
* Re-exported the _octseq_ crate as `dep::octseq`. ([#230])
* Added a blanket impl for mut refs to `Composer`. ([#231] by [@xofyarg])

[#216]: https://github.com/NLnetLabs/domain/pull/216
[#229]: https://github.com/NLnetLabs/domain/pull/229
[#230]: https://github.com/NLnetLabs/domain/pull/230
[#231]: https://github.com/NLnetLabs/domain/pull/231
[#232]: https://github.com/NLnetLabs/domain/pull/232
[#235]: https://github.com/NLnetLabs/domain/pull/235
[@WhyNotHugo]: https://github.com/WhyNotHugo
[@xofyarg]: https://github.com/xofyarg


## 0.8.1

Released 2023-09-18

New

* Added a new method `FoundSrvs::into_srvs` that converts the value into an
  iterator over the found SRV records without resolving them further.
  ([#174], [#214] by [@WhyNotHugo]); this was added in 0.7.2 but missing
  in 0.8.0)
* Added impl of `Borrow<Dname<[u8]>>` and `AsRef<Dname<[u8]>>` for
  `Dname<_>`. ([#219] by [@iximeow}], [#225])
* Added `Dname::fmt_with_dot` that can be used when wanting to display a
  domain name with a dot at the end. ([#210])

Bug Fixes

* Fixed trait bounds on `FoundSrvs::into_stream` to make it usable again.
  ([#174], [#214 by [@WhyNotHugo]]; this was fixed in 0.7.2 but missing in
  0.8.0)
* Fixed scanning of domain names that are just the root label. ([#210])
* Fixed `util::base64::SymbolConverter` to also include the final group in
  the output if there is padding. ([#212])

[#174]: https://github.com/NLnetLabs/domain/pull/174
[#210]: https://github.com/NLnetLabs/domain/pull/210
[#212]: https://github.com/NLnetLabs/domain/pull/212
[#214]: https://github.com/NLnetLabs/domain/pull/214
[#219]: https://github.com/NLnetLabs/domain/pull/219
[#225]: https://github.com/NLnetLabs/domain/pull/225
[@iximeow]: https://github.com/iximeow
[@WhyNotHugo]: https://github.com/WhyNotHugo


## 0.8.0

Released 2023-05-12

Breaking Changes

* The minimal required Rust version is now 1.65. ([#160])
* The `random` feature has been dropped in favour of using `rand`.
  ([#204])
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
* The `Deref` and `DerefMut` impls have been removed for most types that
  had them to follow guidance that they are exclusively for use by pointer
  types – which none of them are. `len` and `is_empty` methods have been
  added where appropriate, additional methods may be added. ([#205])
* Various functions and methods of the `tsig` module now expect the
  current time as an argument to allow use of the module in a no-std
  environment. ([#152])
* Parsing of representation format and zonefiles has been completely
  re-written. ([#142], based on work in [#109] by [Martin Fischer])
* All types that wrap an octets sequence only now allow unsized octets
  sequence types. They all have an associated function `from_slice` to
  create a reference to a value wrapping an (unsized) octets slice and
  method `for_slice` that converts a `&self` into such a reference. Where
  the latter already existed but returned a value wrapping a `&[u8]` (e.g.,
  `Dname<_>` and `Message<_>`, the return type has changed accordingly.
  ([#168])
* Removed `CharStr::from_bytes`. Use `CharStr::from_octets` instead. ([#168])
* `Message::from_octets` now returns a new error type `ShortMessage`. ([#168])
* Dropped `Deref` impls for `Dname<_>`, `RelativeDname<_>`. ([#168])
* Renamed `opt::KeyTag::new` to `opt::KeyTag::from_octets`. ([#168])
* Renamed `rdata::Txt::try_from_slice` to `build_from_slice`. ([#168])
* The `new` method of the following record data types now check whether
  the wire format representation of the record data is too long and thus
  returns a result: `Tsig<_, _>`, `Dnskey<_>`, `Rrsig<_, _>`, `Ds<_>`, 
  `Cdnskey<_>`, `Cds<_>`. ([#169])
* The `new` function for `rdata::Null<_>` has been replaced with a
  `from_octets` and `from_slice` pair. The `Deref` impl was removed. ([#169])
* The `rdata::svcb` module has been refactored to work in the same way as
  other type-length-value constructs. The names of types, methods, and
  functions have changed both to match the usual nomenclature as well as
  to match the terms used in the SVCB draft. ([#176])
* The `base::iana::SvcbParamKey` type has been renamed to `SvcParamKey`
  to match the terms used in the SVCB draft. ([#176])
* The `TcpKeepalive` option has been changed to use an `Option<u16>` as
  its data and allow for an empty option in accordance with the RFC.
  ([#185])
* Renamed the sub-modules of `rdata` that contain record data types to use a
  name derived from their content rather than their RFC number – with the
  exception of `rdata::rfc1035`. ([#189])
* Renamed the sub-modules of `base::opt` that contain option data types to
  use short-hand names rather than their RFC number. ([#190])
* TTL values are now using a newtype `base::record::Ttl` that wraps the
  raw `u32` and improves conversions. ([#202] by [@CrabNejonas])
* Changes all option data types to ensure their wire format is at most
  65,535 octets long. This requires changing the signatures of some
  creator functions. Their naming scheme and signatures are also changed
  to follow the pattern established with record data. ([#193])
* Renamed `UnknownOptData::from_octets` to `new` and return a result. ([#193])
* Completely redesigns DNS cookie options, adding support for standard server
  cookies introduced in RFC 9018. ([#193])
* Change the type of `ExtendedError`’s text to `Str<Octs>` and change the
  return type of `set_text` to `()`. ([#193])
* Changed the type `TcpKeepalive`’s content to a newtype `IdleTimeout` to
  make it easier to convert to and from durations. ([#193])
* Changes Padding to just contain the padding octets and drop `PaddingMode`.
  Instead, the methods on `OptBuilder` should be used to add padding. ([#193])

New

* `Display` impls are now available for all EDNS0 options. ([#157])
* Adds a `FromStr` implementation and related functions to
  `RelativeDname`. ([#177])
* Add a `Debug` impl to `base::message::Message` so it can be unwrapped
  etc. ([#199])
* New methods `make_canonical` on `Dname` and `RelativeDname` that convert
  the name into its canonical, i.e., lowercase form. Similarly, new
  methods `ToDname::to_canonical_dname` and
  `ToRelativeDname::to_canonical_relative_dname` that produce new
  canonical names. ([#200])
* Added a `MAX_LEN` constant to various types that wrap length-limited
  octets sequences. ([#201] by [@CrabNejonas])

[#109]: https://github.com/NLnetLabs/domain/pull/109
[#142]: https://github.com/NLnetLabs/domain/pull/142
[#152]: https://github.com/NLnetLabs/domain/pull/152
[#157]: https://github.com/NLnetLabs/domain/pull/157
[#160]: https://github.com/NLnetLabs/domain/pull/160
[#168]: https://github.com/NLnetLabs/domain/pull/168
[#169]: https://github.com/NLnetLabs/domain/pull/169
[#176]: https://github.com/NLnetLabs/domain/pull/176
[#177]: https://github.com/NLnetLabs/domain/pull/177
[#185]: https://github.com/NLnetLabs/domain/pull/185
[#189]: https://github.com/NLnetLabs/domain/pull/189
[#190]: https://github.com/NLnetLabs/domain/pull/190
[#193]: https://github.com/NLnetLabs/domain/pull/193
[#199]: https://github.com/NLnetLabs/domain/pull/199
[#200]: https://github.com/NLnetLabs/domain/pull/200
[#201]: https://github.com/NLnetLabs/domain/pull/201
[#202]: https://github.com/NLnetLabs/domain/pull/202
[#204]: https://github.com/NLnetLabs/domain/pull/204
[#205]: https://github.com/NLnetLabs/domain/pull/205
[Martin Fischer]: https://push-f.com/
[@CrabNejonas]: https://github.com/CrabNejonas
[octseq]: https://crates.io/crates/octseq


## 0.7.2

Released 2023-03-02

New

* Added a new method `FoundSrvs::into_srvs` that converts the value into an
  iterator over the found SRV records without resolving them further.
  ([#174])

Bug Fixes

* Fix trait bounds on `FoundSrvs::into_stream` to make it usable again.
  ([#174])

[#174]: https://github.com/NLnetLabs/domain/pull/174


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

