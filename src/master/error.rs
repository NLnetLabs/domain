
use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::result;
use std::str::Utf8Error;
use ::master::Pos;


//------------ SyntaxError ---------------------------------------------------

pub enum SyntaxError {
    Expected(Vec<u8>),
    ExpectedNewline,
    ExpectedSpace,
    IllegalEscape,
    IllegalInteger,
    IllegalAddr(AddrParseError),
    IllegalString(Utf8Error),
    LongCharStr,
    LongLabel,
    LongName,
    LongGenericData,
    NestedParentheses,
    NoDefaultTtl,
    NoLastClass,
    NoLastOwner,
    NoOrigin,
    RelativeName,
    Unexpected(u8),
    UnexpectedEof,
    UnknownClass(Vec<u8>),
    UnknownProto(String),
    UnknownServ(String),
}

impl From<ParseIntError> for SyntaxError {
    fn from(_: ParseIntError) -> SyntaxError {
        SyntaxError::IllegalInteger
    }
}

impl From<AddrParseError> for SyntaxError {
    fn from(err: AddrParseError) -> SyntaxError {
        SyntaxError::IllegalAddr(err)
    }
}

impl From<Utf8Error> for SyntaxError {
    fn from(err: Utf8Error) -> SyntaxError {
        SyntaxError::IllegalString(err)
    }
}

//------------ Error ---------------------------------------------------------

pub enum Error {
    Io(io::Error),
    Syntax(SyntaxError, Pos)
}

impl Error {
    pub fn is_eof(&self) -> bool {
        if let Error::Syntax(SyntaxError::UnexpectedEof, _) = *self { true }
        else { false }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}


//------------ Result --------------------------------------------------------

pub type Result<T> = result::Result<T, Error>;
pub type SyntaxResult<T> = result::Result<T, SyntaxError>;
