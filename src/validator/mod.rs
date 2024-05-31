// Validator

#![cfg(all(feature = "validate", feature = "unstable-client-transport"))]

//! This module provides a DNSSEC validator.
//! DNSSEC validation requires a trust anchor. A trust anchor can be
//! created using [anchor::TrustAnchors].
//! The trust anchor is then used, together with a [crate::net::client]
//! transport and optionally a [context::Config] to create a DNSSEC
//! validation [context::ValidationContext].
//! The validation context then provides the
//! method [context::ValidationContext::validate_msg()] to validate a
//! reply message.

pub mod anchor;
pub mod context;
mod group;
mod nsec;
pub mod types;
mod utilities;
