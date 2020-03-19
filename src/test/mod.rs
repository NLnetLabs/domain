//! Tooling for interop testing.
//!
//! This project provides the scaffolding for testing the interoperability of
//! the `domain` crate with various other DNS implementations out there.
//!
//! The actual tests live with their respective modules in a sub-module called
//! `interop`. Since they require additional software packages to be available
//! and can be expensive, they are only run if the `"interop"` feature is
//! given to `cargo test`.
//!
#![cfg(all(test, feature = "interop"))]

pub mod cargo;
pub mod nsd;
pub mod utils;

