use std::borrow::Cow;
use std::num::ParseIntError;
use std::string::ParseError;
use std::{error, fmt, io};

#[derive(Clone, Debug)]
pub struct Error {
    message: Cow<'static, str>,
}

impl From<&'static str> for Error {
    fn from(message: &'static str) -> Self {
        Self {
            message: Cow::Borrowed(message),
        }
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self {
            message: Cow::Owned(message),
        }
    }
}

impl From<ParseError> for Error {
    fn from(_err: ParseError) -> Self {
        Self::from("message parse error")
    }
}

impl From<ParseIntError> for Error {
    fn from(_err: ParseIntError) -> Self {
        Self::from("message parse error")
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::from(err.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.message, f)
    }
}

impl error::Error for Error {}