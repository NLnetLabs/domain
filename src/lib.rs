//! A DNS library for Rust.
//!
//! This crate provides a wide range of modules related to the Domain Name
//! System. Currently, these are:
//!
//! * fundamental types, traits, and implementations for dealing with DNS
//!   data through the modules [bits], [rdata], and [iana],
//! * an asynchronous stub resolver implementation for querying the DNS
//!   in [resolv],
//! * facilities to build a name server in the [server] module.
//!
//! [bits]: bits/index.html
//! [iana]: iana/index.html
//! [rdata]: rdata/index.html
//! [resolv]: resolv/index.html
//! [server]: server/index.html

extern crate rand;
extern crate rotor;
extern crate vecio;

pub mod bits;
pub mod iana;
pub mod master;
pub mod rdata;
pub mod resolv;
pub mod server;
pub mod utils;

