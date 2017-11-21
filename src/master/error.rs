/// Errors when dealing with master data.

use std::net::AddrParseError;
use std::num::ParseIntError;
use std::result;
use std::str::Utf8Error;
use ::bits::name;
use super::scanner::Symbol;


//------------ SyntaxError ---------------------------------------------------

/// A syntax error happened while scanning master data.
#[derive(Clone, Debug, PartialEq)]
pub enum SyntaxError {
    Expected(String),
    ExpectedNewline,
    ExpectedSpace,
    IllegalChar(char),
    IllegalEscape,
    IllegalInteger,
    IllegalAddr(AddrParseError),
    IllegalName,
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
    Unexpected(Symbol),
    UnexpectedEof,
    UnknownClass(String),
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

#[allow(match_same_arms)]
impl From<name::FromStrError> for SyntaxError {
    fn from(err: name::FromStrError) -> SyntaxError {
        match err {
            name::FromStrError::UnexpectedEnd => SyntaxError::UnexpectedEof,
            name::FromStrError::EmptyLabel => SyntaxError::IllegalName,
            name::FromStrError::BinaryLabel => SyntaxError::IllegalName,
            name::FromStrError::LongLabel => SyntaxError::LongLabel,
            name::FromStrError::IllegalEscape => SyntaxError::IllegalEscape,
            name::FromStrError::IllegalCharacter => SyntaxError::IllegalName,
            name::FromStrError::LongName => SyntaxError::LongName,
        }
    }
}


//------------ SyntaxError ---------------------------------------------------

/// A result with a syntax error.
pub type SyntaxResult<T> = result::Result<T, SyntaxError>;

//------------ ScanError -----------------------------------------------------

/// An error happened while scanning master data.
#[derive(Debug)]
pub enum ScanError<S> {
    Source(S, Pos),
    Syntax(SyntaxError, Pos),
}


//------------ Pos -----------------------------------------------------------

/// The human-friendly position in a reader.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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

    pub fn update(&mut self, ch: Symbol) {
        match ch {
            Symbol::Char(_) => self.col += 1,
            Symbol::SimpleEscape(_) => self.col += 2,
            Symbol::DecimalEscape(_) => self.col += 4,
            Symbol::Newline => { self.line += 1; self.col = 1 }
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

