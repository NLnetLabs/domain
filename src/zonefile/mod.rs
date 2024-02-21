//! Reading and writing of zonefiles.
#![cfg(feature = "zonefile")]
#![cfg_attr(docsrs, doc(cfg(feature = "zonefile")))]

pub mod inplace;
pub mod parsed;