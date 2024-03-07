//! Various utility modules.
//!
//! This should probably be separate crates …

pub mod base16;
pub mod base32;
pub mod base64;

#[cfg(feature = "net")]
pub(crate) mod config;
