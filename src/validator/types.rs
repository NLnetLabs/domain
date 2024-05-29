// Collection of usefull types.

use crate::base::message::ShortMessage;
use crate::base::name;
use crate::base::wire;
use crate::zonefile::inplace;
use std::sync::Arc;

// RFC 4033, Section 5 defines the security states of data:
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ValidationState {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

#[derive(Debug)]
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
