//! Cross-module error types.

use std::{error, fmt};

//------------ ShortParser ---------------------------------------------------

/// An attempt was made to go beyond the end of a buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortBuf;

impl error::Error for ShortBuf {
    fn description(&self) -> &str {
        "unexpected end of data"
    }
}

impl fmt::Display for ShortBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}

