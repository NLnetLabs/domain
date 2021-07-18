//! Reading and writing of master files.
//!
//! **This module is experimental and likely to change.**
#![cfg(feature = "master")]
#![cfg_attr(docsrs, doc(cfg(feature = "master")))]

pub mod entry;
pub mod reader;
pub mod scan;
pub mod source;
