
use std::io;
use std::num::ParseIntError;
use std::result;
use ::master::Pos;


//------------ SyntaxError ---------------------------------------------------

pub enum SyntaxError {
    Expected(Vec<u8>),
    ExpectedNewline,
    IllegalEscape,
    IllegalInteger,
    LongLabel,
    LongName,
    NestedParentheses,
    NoDefaultTtl,
    NoLastClass,
    NoLastOwner,
    RelativeName,
    Unexpected(u8),
    UnexpectedEof,
    UnknownClass(Vec<u8>),
}

impl From<ParseIntError> for SyntaxError {
    fn from(_: ParseIntError) -> SyntaxError {
        SyntaxError::IllegalInteger
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
