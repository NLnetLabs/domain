//! Reading and writing of zonefiles.
#![cfg(feature = "zonefile")]
#![cfg_attr(docsrs, doc(cfg(feature = "zonefile")))]

pub mod error;
pub mod inplace;
#[cfg(feature = "unstable-zonetree")]
pub mod parsed;
