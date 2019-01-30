//! A DNS library for Rust – Meta Crate.
//!
//! This crate imports all crates of the _domain_ family and re-exports their
//! content under one common base.
//!
//! Currently, these are:
//!
//! * [domain-core](core/index.html) under `domain::core`,
//! * [domain-resolv](resolv/index.html) under `domain::resolv`.

pub extern crate domain_core as core;
pub extern crate domain_resolv as resolv;

