//! A DNS library for Rust.
//!
//! This crates provides a number of bulding blocks for developing
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
//! * [master]: Experimental reading and writing of master files – also known
//!   as zone files –, i.e., the textual representation of DNS data. This
//!   module will be re-implemented in the near future and will be renamed to
//!   _zonefiles._
//! * [resolv]: An asynchronous DNS resolver based on the
//!   [Tokio](https://tokio.rs/) async runtime.
//! * [sign]: Experimental support for DNSSEC signing.
//! * [tsig]: Support for securing DNS transactions with TSIG records.
//! * [validate]: Experimental support for DNSSEC validation.
//!
//!
//! # Reference of Feature Flags
//!
//! The following is the complete list of the feature flags available.
//!
//! * `bytes`: Rnables using the types `Bytes` and `BytesMut` from the
//!    [bytes](https://github.com/tokio-rs/bytes) crate as octet sequences.
//! * `chrono`: Adds the [chrono](https://github.com/chronotope/chrono)
//!   crate as a dependency. This adds support for generating serial numbers
//!   from time stamps.
//! * `heapless`: enables the use of the `Vec` type from the
//!   [heapless](https://github.com/japaric/heapless) crate as octet
//!   sequences.
//! * `master`: Zone file parsing and construction. This will enable the
//!   [master] module and currently enables the `bytes`, `chrono`, and `std`
//!   features. Note that feature and module are experimental and will soon
//!   be replaced.
//! * `resolv`: Enables the asynchronous stub resolver via the [resolv]
//!   module.
//! * `ring`: Enables crypto functionality via the
//!   [ring](https://github.com/briansmith/ring) crate.
//! * `sign`: basic DNSSEC signing support. This will enable the [sign]
//!   module and requires the `std` feature. Note that this will not directly
//!   enable actually signing. For that you will also need to pick a crypto
//!   module via an additional feature. Currently we only support the `ring`
//!   module, but support for OpenSSL is coming soon.
//! * `smallvec`: enables the use of the `Smallvec` type from the
//!   [smallvec](https://github.com/servo/rust-smallvec) crate as octet
//!   sequences.
//! * `std`: support for the Rust std library. This feature is enabled by
//!   default.
//! * `tsig`: support for signing and validating message exchanges via TSIG
//!   signatures. This enables the [tsig] module and currently pulls in the
//!   `bytes`, `ring`, and `smallvec` features.
//! * `validate`: basic DNSSEC validation support. This feature enables the
//!   [validate] module and currently also enables the `std` and `ring`
//!   features.

#![no_std]
#![allow(renamed_and_removed_lints)]
#![allow(clippy::unknown_clippy_lints)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(feature = "std"))]
#[allow(unused_imports)] // Import macros even if unused.
#[macro_use]
extern crate std;

#[macro_use]
extern crate core;

pub mod base;
pub mod master;
pub mod rdata;
pub mod resolv;
pub mod sign;
pub mod test;
pub mod tsig;
pub mod utils;
pub mod validate;
