// Collection of usefull types.

use crate::base::wire;

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
    ParseError,
}

impl From<wire::ParseError> for Error {
    fn from(_: wire::ParseError) -> Self {
        Error::ParseError
    }
}
