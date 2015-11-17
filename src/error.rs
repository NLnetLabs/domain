//! High-level error type
//!

use std::error::Error as StdError;
use std::fmt;
use super::name;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    NameError(name::Error),
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::NameError(ref e) => e.description()
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::NameError(ref err) => Some(err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(f)
    }
}
