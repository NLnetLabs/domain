//! DNSSEC signing and validation
//!
#![cfg_attr(any(feature = "ring", feature = "openssl"), doc = "* [common]:")]
#![cfg_attr(
    not(any(feature = "ring", feature = "openssl")),
    doc = "* common:"
)]
//! Types and functions that are common between signing and validation.
#![cfg_attr(
    all(
        feature = "unstable-sign",
        any(feature = "ring", feature = "openssl")
    ),
    doc = "* [sign]:"
)]
#![cfg_attr(
    not(all(
        feature = "unstable-sign",
        any(feature = "ring", feature = "openssl")
    )),
    doc = "* sign:"
)]
//! Experimental support for DNSSEC signing.
#![cfg_attr(
    all(
        feature = "unstable-validator",
        any(feature = "ring", feature = "openssl")
    ),
    doc = "* [validator]:"
)]
#![cfg_attr(
    not(all(
        feature = "unstable-validator",
        any(feature = "ring", feature = "openssl")
    )),
    doc = "* validator:"
)]
//! Experimental support for DNSSEC validation.
//!
//! Note that in addition to the feature flags that enable the various modules
//! (`unstable-sig`, `unstable-validator`), at least one cryptographic
//! backend needs to be selected (currently there are `ring` and `openssl`).

pub mod common;
pub mod sign;
pub mod validator;
