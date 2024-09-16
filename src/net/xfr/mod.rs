#![cfg_attr(
    not(feature = "unstable-xfr"),
    doc = " The `unstable-xfr` feature is necessary to enable this module."
)]
// #![warn(missing_docs)]
// #![warn(clippy::missing_docs_in_private_items)]
//! XFR protocol related functionality.
pub mod protocol;
