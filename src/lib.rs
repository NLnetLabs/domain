//! A DNS library for Rust.
//!
//! This crates provides a number of bulding blocks for developing
//! functionality related to the DNS. It provides fundamental types, traits,
//! and code as well as a wide range of optional features. The intent is to
//! eventually cover all aspects of the DNS.
//!
//! # Modules
//!
//! The most important module is [base]. It contains a wide variety of types,
//! traits, and functionality to deal with DNS data. The module [rdata]
//! contains types and implementations for a growing number of record types.
//!
//! In addition to those two basic modules, there are a number of modules for
//! more specific features that are not required in all applications. In order
//! to keep the amount of code to be compiled and the number of dependencies
//! small, these are hidden behind feature flags through which they can be
//! enabled if required. The flags have the same names as the modules.
//!
//! Currently, there are the following modules:
//!
//! * [master]: reading and writing of master files – also known as zone
//!   files –, i.e., the textual representation of DNS data.
//! * [sign]: support for DNSSEC signing,
//! * [tsig]: support for securing DNS transactions with TSIG records,
//! * [validate]: support for DNSSEC validation.
//!
//! One missing module is _resolv,_ which implements an asynchronous DNS
//! resolver. This module currently resides in its own crate [domain-resolv]
//! do to restrictions for async functions used by the module and will be
//! transfered here as soon as possible.
//!
//! A few additional feature flags that enable the use of other crates either
//! by adding features to this crate or by implementing traits for types
//! defined by those crates. See the overview of feature flags below.
//!
//! # Overview of Feature Flags
//!
//! The following feature flags are available to select optional parts of
//! the crate and to keep the amount of compiled code and dependencies small
//! if these parts are not required.
//!
//! * `bytes`: enables using the types `Bytes` and `BytesMut` from the
//!    [bytes] crate as octet sequences.
//! * `chrono`: adds the [chrono] crate as a dependency. This adds support
//!   for generating serial numbers from time stamps.
//! * `master`: master file (also known as zone file) parsing and
//!   construction. This will enable the [master] module and currently
//!   enables the `bytes`, `chrono`, and `std` features.
//! * `ring`: enables crypto functionality via the [ring] crate.
//! * `sign`: basic DNSSEC signing support. This will enable the [sign]
//!   module and requires the `std` feature. Note that this will not directly
//!   enable actually signing. For that you will also need to pick a crypto
//!   module via an additional feature. Currently we only support the `ring`
//!   module, but support for OpenSSL is coming soon.
//! * `smallvec`: enables the use of the `Smallvec` type from the [smallvec]
//!   crate as octet sequences.
//! * `std`: support for the Rust std library. This feature is enabled by
//!   default.
//! * `tsig`: support for signing and validating message exchanges via TSIG
//!   signatures. This enables the [tsig] module and currently pulls in the
//!   `bytes`, `ring`, and `smallvec` features.
//! * `validate`: basic DNSSEC validation support. This feature enables the
//!   [validate] module and currently also enables the `std` and `ring`
//!   features.
//!
//! [base]: base/index.html
//! [master]: master/index.html
//! [rdata]: rdata/index.html
//! [sign]: sign/index.html
//! [tsig]: tsig/index.html
//! [validate]: valiate/index.html
//! [bytes]: https://docs.rs/bytes/
//! [domain-resolv]: https://docs.rs/domain-resolv/
//! [chrono]: https://docs.rs/chrono/
//! [ring]: https://docs.rs/ring/
//! [smallvec]: https://docs.rs/smallvec/

#![no_std]

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
