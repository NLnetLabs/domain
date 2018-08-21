//! A DNS library for Rust – Core.
//!
//! This crate provides a number of modules related to the core functionality 
//! of the Domain Name System. Currently, these are:
//!
//! * fundamental types, traits, and implementations for dealing with DNS
//!   data through the modules [bits] and [iana],
//! * parsing of master file data (aka zonefiles) in [master],
//! * data and master file access for various resource record types in
//!   [rdata].
//!
//! [bits]: bits/index.html
//! [iana]: iana/index.html
//! [master]: master/index.html
//! [rdata]: rdata/index.html
#![allow(unknown_lints)] // hide clippy-related #allows on stable. 

extern crate bytes;
extern crate chrono;
extern crate failure;
#[macro_use] extern crate failure_derive;
extern crate rand;

pub mod bits;
pub mod iana;
pub mod master;
pub mod rdata;
pub mod utils;
