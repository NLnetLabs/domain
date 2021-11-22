//! Networking-related types not available in core.
//!
//! This module either re-exports or re-defines a number of types related to
//! networking that are not available in a `no_std` environment but are used
//! in DNS data. Currently, these are types for IP addresses.
//!
//! The `no_std` version currently is only the bare minimum implementation
//! and doesn’t provide all the features the `std` version has.

#[cfg(feature = "std")]
pub use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(not(feature = "std"))]
pub use self::nostd::*;

mod nostd;
mod parser;
