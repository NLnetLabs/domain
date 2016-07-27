
use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::result;
use std::str::Utf8Error;
use ::bits::name::NameError;


//------------ SyntaxError ---------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum SyntaxError {
    Expected(Vec<u8>),
    ExpectedNewline,
    ExpectedSpace,
    IllegalEscape,
    IllegalInteger,
    IllegalAddr(AddrParseError),
    IllegalName(NameError),
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

impl From<NameError> for SyntaxError {
    fn from(err: NameError) -> SyntaxError {
        SyntaxError::IllegalName(err)
    }
}

impl From<Utf8Error> for SyntaxError {
    fn from(err: Utf8Error) -> SyntaxError {
        SyntaxError::IllegalString(err)
    }
}

//------------ ScanError -----------------------------------------------------

#[derive(Debug)]
pub enum ScanError {
    Io(io::Error),
    Syntax(SyntaxError, Pos)
}

impl ScanError {
    pub fn is_eof(&self) -> bool {
        if let ScanError::Syntax(SyntaxError::UnexpectedEof, _) = *self {
            true
        }
        else { false }
    }
}

impl From<io::Error> for ScanError {
    fn from(err: io::Error) -> ScanError {
        ScanError::Io(err)
    }
}


//------------ ScanResult ----------------------------------------------------

pub type ScanResult<T> = result::Result<T, ScanError>;
pub type SyntaxResult<T> = result::Result<T, SyntaxError>;


//------------ Pos -----------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pos {
    line: usize,
    col: usize
}

impl Pos {
    pub fn new() -> Pos {
        Pos { line: 1, col: 1 }
    }

    pub fn line(&self) -> usize { self.line }
    pub fn col(&self) -> usize { self.col }

    pub fn update(&mut self, ch: u8) {
        match ch {
            b'\n' => { self.line += 1; self.col = 1 }
            _ => self.col += 1
        }
    }

    pub fn prev(&self) -> Pos {
        Pos { line: self.line,
              col: if self.col <= 1 { 1 } else { self.col - 1 }
        }
    }
}

impl From<(usize, usize)> for Pos {
    fn from(src: (usize, usize)) -> Pos {
        Pos { line: src.0, col: src.1 }
    }
}

impl PartialEq<(usize, usize)> for Pos {
    fn eq(&self, other: &(usize, usize)) -> bool {
        self.line == other.0 && self.col == other.1
    }
}

