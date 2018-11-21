//! An asynchronous DNS stub resolver.
//!
//! A resolver is the component in the DNS that answers queries. A stub
//! resolver does so by simply relaying queries to a different resolver
//! chosen from a predefined set. This is how pretty much all user
//! applications use DNS.
//!
//! This module implements a modern, asynchronous stub resolver built on
//! top of [futures] and [tokio].
#![allow(unknown_lints)] // hide clippy-related #allows on stable. 

extern crate domain_core;
#[macro_use] extern crate futures;
extern crate rand;
extern crate tokio;

pub mod conf;
pub mod lookup;
pub mod resolver;
pub mod search;

pub mod net;

