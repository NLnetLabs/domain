//! A DNS library for Rust.
//!
//! This crate provides a wide range of modules related to the Domain Name
//! System. Currently, these are:
//!
//! * fundamental types, traits, and implementations for dealing with DNS
//!   data through the modules [bits](bits/index.html),
//!   [rdata](rdata/index.html), and [iana](iana/index.html),
//! * an asynchronous stub resolver implementation for querying the DNS
//!   in [resolv](resolv/index.html).

extern crate rand;
extern crate rotor;
extern crate vecio;

pub mod bits;
pub mod iana;
pub mod rdata;
pub mod resolv;

