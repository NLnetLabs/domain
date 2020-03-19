//! A DNS library for Rust.

#![no_std]

#[cfg(any(feature = "std"))]
#[allow(unused_imports)] // Import macros even if unused.
#[macro_use] extern crate std;

#[macro_use] extern crate core;

pub mod base;
pub mod master;
pub mod rdata;
pub mod resolv;
pub mod sign;
pub mod test;
pub mod tsig;

