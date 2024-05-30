// Collection of usefull types.

use crate::base::message::ShortMessage;
use crate::base::name;
use crate::base::wire;
use crate::zonefile::inplace;
use std::error;
use std::fmt;
use std::sync::Arc;

// RFC 4033, Section 5 defines the security states of data:
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ValidationState {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

#[derive(Clone, Debug)]
pub enum Error {
    FormError,
    InplaceError(inplace::Error),
    OctetsConversion,
    ParseError,
    PushError,
    PushNameError,
    ReadError(Arc<std::io::Error>),
    ShortMessage,
}

impl From<inplace::Error> for Error {
    fn from(e: inplace::Error) -> Self {
        Error::InplaceError(e)
    }
}

impl From<name::PushError> for Error {
    fn from(_: name::PushError) -> Self {
        Error::PushError
    }
}

impl From<name::PushNameError> for Error {
    fn from(_: name::PushNameError) -> Self {
        Error::PushNameError
    }
}

impl From<wire::ParseError> for Error {
    fn from(_: wire::ParseError) -> Self {
        Error::ParseError
    }
}

impl From<ShortMessage> for Error {
    fn from(_: ShortMessage) -> Self {
        Error::ShortMessage
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::FormError => write!(f, "FormError"),
            Error::InplaceError(_) => write!(f, "InplaceError"),
            Error::OctetsConversion => write!(f, "OctetsConversion"),
            Error::ParseError => write!(f, "ParseError"),
            Error::PushError => write!(f, "PushError"),
            Error::PushNameError => write!(f, "PushNameError"),
            Error::ReadError(_) => write!(f, "FormError"),
            Error::ShortMessage => write!(f, "ShortMEssage"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::FormError => None,
            Error::InplaceError(err) => Some(err),
            Error::OctetsConversion => None,
            Error::ParseError => None,
            Error::PushError => None,
            Error::PushNameError => None,
            Error::ReadError(err) => Some(err),
            Error::ShortMessage => None,
        }
    }
}
