//! DNSSEC signing and validation
//!
#![cfg_attr(feature = "unstable-crypto-backend", doc = "* [common]:")]
#![cfg_attr(not(feature = "unstable-crypto-backend"), doc = "* common:")]
//! Types and functions that are common between signing and validation.
#![cfg_attr(feature = "unstable-sign", doc = "* [sign]:")]
#![cfg_attr(not(feature = "unstable-sign"), doc = "* sign:")]
//! Experimental support for DNSSEC signing.
#![cfg_attr(feature = "unstable-validator", doc = "* [validator]:")]
#![cfg_attr(not(feature = "unstable-validator"), doc = "* validator:")]
//! Experimental support for DNSSEC validation.
//!
//! Note that in addition to the feature flags that enable the various modules
//! (`unstable-sig`, `unstable-validator`), at least one cryptographic
//! backend needs to be selected (currently there are `ring` and `openssl`).

pub mod common;
pub mod sign;
pub mod validator;
