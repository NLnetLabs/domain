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

// All the unstable features we need to make this work.
#![feature(arbitrary_self_types, async_await, await_macro, futures_api, pin)]

extern crate domain_core;
extern crate futures;
extern crate futures_util;
extern crate tokio;

pub use self::conf::ResolvConf;
pub use self::resolver::Resolver;

pub mod conf;
pub mod resolver;

mod net;
