//! A DNS library for Rust – Meta Crate.
//!
//! This crate imports all crates of the _domain_ family and re-exports their
//! content under one common base.
//!
//! Currently, these are:
//!
//! * [domain-core](../domain_core/index.html) under `domain::core`,
//! * [domain-resolv](domain_resolv/index.html) under `domain::resolv`.
//! * [domain-tsig](domain_tsig/index.html) under `domain::tsig`.
//!
//! Note that all but the `domain::core` re-export are optional and need
//! to be selected via features.

pub extern crate domain_core as core;
#[cfg(feature = "resolv")] pub extern crate domain_resolv as resolv;
#[cfg(feature = "tsig")] pub extern crate domain_tsig as tsig;

