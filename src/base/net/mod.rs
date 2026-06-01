//! Networking-related types not available in core.
//!
//! This module used to re-define networking types not provided by `core`.
//! As of Rust 1.77, `core` now provides them, so this module is deprecated.

#![deprecated = "Use 'core::net::*' instead"]

pub use core::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
