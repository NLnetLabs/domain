//! A DNS library for Rust.
//!
//! This crates provides a number of building blocks for developing
//! functionality related to the DNS. It provides fundamental types, traits,
//! and code as well as a wide range of optional features. The intent is to
//! eventually cover all aspects of modern DNS.
//!
//! The crate uses feature flags to allow you to select only those modules
//! you need for you particular project. In most cases, the feature names
//! are equal to the module they enable.
//!
//! # Modules
//!
//! A set of modules providing fundamental types and functionality is always
//! enabled:
//!
//! * [base] contains a wide variety of types, traits, and functionality
//!   to deal with DNS data, and
//! * [rdata] contains types and implementations for a growing number of
//!   record types.
//!
//! In addition to those two basic modules, there are a number of modules for
//! more specific features that are not required in all applications. In order
//! to keep the amount of code to be compiled and the number of dependencies
//! small, these are hidden behind feature flags through which they can be
//! enabled if required. The flags have the same names as the modules.
//!
//! Currently, there are the following modules:
//!
#![cfg_attr(feature = "net", doc = "* [net]:")]
#![cfg_attr(not(feature = "net"), doc = "* net:")]
//!   Sending and receiving DNS messages.
#![cfg_attr(feature = "resolv", doc = "* [resolv]:")]
#![cfg_attr(not(feature = "resolv"), doc = "* resolv:")]
//!   An asynchronous DNS resolver based on the
//!   [Tokio](https://tokio.rs/) async runtime.
#![cfg_attr(feature = "sign", doc = "* [sign]:")]
#![cfg_attr(not(feature = "sign"), doc = "* sign:")]
//!   Experimental support for DNSSEC signing.
#![cfg_attr(feature = "tsig", doc = "* [tsig]:")]
#![cfg_attr(not(feature = "tsig"), doc = "* tsig:")]
//!   Support for securing DNS transactions with TSIG records.
#![cfg_attr(feature = "validate", doc = "* [validate]:")]
#![cfg_attr(not(feature = "validate"), doc = "* validate:")]
//!   Experimental support for DNSSEC validation.
#![cfg_attr(feature = "zonefile", doc = "* [zonefile]:")]
#![cfg_attr(not(feature = "zonefile"), doc = "* zonefile:")]
//!   Experimental reading and writing of zone files, i.e. the textual
//!   representation of DNS data.
#![cfg_attr(feature = "unstable-zonetree", doc = "* [zonetree]:")]
#![cfg_attr(not(feature = "unstable-zonetree"), doc = "* zonetree:")]
//!   Experimental storing and querying of zone trees.
//!
//! Finally, the [dep] module contains re-exports of some important
//! dependencies to help avoid issues with multiple versions of a crate.
//!
//! # Reference of feature flags
//!
//! The following is the complete list of the feature flags with the
//! exception of unstable features which are described below.
//!
//! * `bytes`: Enables using the types `Bytes` and `BytesMut` from the
//!   [bytes](https://github.com/tokio-rs/bytes) crate as octet sequences.
//! * `chrono`: Adds the [chrono](https://github.com/chronotope/chrono)
//!   crate as a dependency. This adds support for generating serial numbers
//!   from time stamps.
//! * `heapless`: enables the use of the `Vec` type from the
//!   [heapless](https://github.com/japaric/heapless) crate as octet
//!   sequences.
//! * `interop`: Activate interoperability tests that rely on other software
//!   to be installed in the system (currently NSD and dig) and will fail if
//!   it isn’t. This feature is not meaningful for users of the crate.
//! * `rand`: Enables a number of methods that rely on a random number
//!   generator being available in the system.
//! * `resolv`: Enables the asynchronous stub resolver via the
#![cfg_attr(feature = "resolv", doc = "  [resolv]")]
#![cfg_attr(not(feature = "resolv"), doc = "  resolv")]
//!   module.
//! * `resolv-sync`: Enables the synchronous version of the stub resolver.
//! * `ring`: Enables crypto functionality via the
//!   [ring](https://github.com/briansmith/ring) crate.
//! * `serde`: Enables serde serialization for a number of basic types.
//! * `sign`: basic DNSSEC signing support. This will enable the
#![cfg_attr(feature = "sign", doc = "  [sign]")]
#![cfg_attr(not(feature = "sign"), doc = "  sign")]
//!   module and requires the `std` feature. Note that this will not directly
//!   enable actual signing. For that you will also need to pick a crypto
//!   module via an additional feature. Currently we only support the `ring`
//!   module, but support for OpenSSL is coming soon.
//! * `siphasher`: enables the dependency on the
//!   [siphasher](https://github.com/jedisct1/rust-siphash) crate which allows
//!   generating and checking hashes in [standard server
//!   cookies][crate::base::opt::cookie::StandardServerCookie].
//! * `smallvec`: enables the use of the `Smallvec` type from the
//!   [smallvec](https://github.com/servo/rust-smallvec) crate as octet
//!   sequences.
//! * `std`: support for the Rust std library. This feature is enabled by
//!   default.
//! * `tsig`: support for signing and validating message exchanges via TSIG
//!   signatures. This enables the
#![cfg_attr(feature = "tsig", doc = "  [tsig]")]
#![cfg_attr(not(feature = "tsig"), doc = "  tsig")]
//!   module and currently pulls in the
//!   `bytes`, `ring`, and `smallvec` features.
//! * `validate`: basic DNSSEC validation support. This feature enables the
#![cfg_attr(feature = "validate", doc = "  [validate]")]
#![cfg_attr(not(feature = "validate"), doc = "  validate")]
//!   module and currently also enables the `std` and `ring`
//!   features.
//! * `zonefile`: reading and writing of zonefiles. This feature enables the
#![cfg_attr(feature = "zonefile", doc = "  [zonefile]")]
#![cfg_attr(not(feature = "zonefile"), doc = "  zonefile")]
//!   module and currently also enables the `bytes` and `std` features.
//!
//! # Unstable features
//!
//! When adding new functionality to the crate, practical experience is
//! necessary to arrive at a good, user friendly design. Unstable features
//! allow adding and rapidly changing new code without having to release
//! versions allowing breaking changes all the time. If you use unstable
//! features, it is best to specify a concrete version as a dependency in
//! `Cargo.toml` using the `=` operator, e.g.:
//!
//! ```text
//! [dependencies]
//! domain = "=0.9.3"
//! ```
//!
//! Currently, the following unstable features exist:
//!
//! * `unstable-client-transport`: sending and receiving DNS messages from
//!   a client perspective; primarily the `net::client` module.
//! * `unstable-server-transport`: receiving and sending DNS messages from
//!   a server perspective; primarily the `net::server` module.
//! * `unstable-zonetree`: building & querying zone trees; primarily the
//!   `zonetree` module.
//!
//! Note: Some functionality is currently informally marked as
//! “experimental” since it was introduced before adoption of the concept
//! of unstable features. These will follow proper Semver practice but may
//! change significantly in releases with breaking changes.

#![no_std]
#![allow(renamed_and_removed_lints)]
#![allow(clippy::unknown_clippy_lints)]
#![allow(clippy::uninlined_format_args)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "std")]
#[allow(unused_imports)] // Import macros even if unused.
#[macro_use]
extern crate std;

#[macro_use]
extern crate core;

pub mod base;
pub mod dep;
pub mod net;
pub mod rdata;
pub mod resolv;
pub mod sign;
pub mod stelline;
pub mod test;
pub mod tsig;
pub mod utils;
pub mod validate;
pub mod validator;
pub mod zonefile;
pub mod zonetree;
