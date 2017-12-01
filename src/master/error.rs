/// Errors when dealing with master data.

use std::io;
use std::net::AddrParseError;
use ::bits::name;
use super::scan::{Symbol, Token};


//------------ SyntaxError ---------------------------------------------------

/// A syntax error happened while scanning master data.
#[derive(Clone, Debug, PartialEq)]
pub enum SyntaxError {
    Expected(String),
    ExpectedNewline,
    ExpectedSpace,
    IllegalEscape,
    IllegalInteger, // TODO Add kind
    IllegalAddr(AddrParseError),
    IllegalName(name::FromStrError),
    LongCharStr,
    UnevenHexString,      // Hex string with an odd number of characters
    LongGenericData,      // More data then given in the length byte
    NestedParentheses,
    NoDefaultTtl,
    NoLastClass,
    NoLastOwner,
    NoOrigin,
    RelativeName,
    Unexpected(Symbol),
    UnexpectedNewline,
    UnexpectedEof,
    UnknownClass(String),
    UnknownProto(String),
    UnknownServ(String),
}

impl From<AddrParseError> for SyntaxError {
    fn from(err: AddrParseError) -> SyntaxError {
        SyntaxError::IllegalAddr(err)
    }
}

impl From<name::FromStrError> for SyntaxError {
    fn from(err: name::FromStrError) -> SyntaxError {
        SyntaxError::IllegalName(err)
    }
}


//------------ ScanError -----------------------------------------------------

/// An error happened while scanning master data.
#[derive(Debug)]
pub enum ScanError {
    Source(io::Error, Pos),
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

    pub fn update(&mut self, ch: Token) {
        match ch {
            Token::Symbol(Symbol::Char(_)) => self.col += 1,
            Token::Symbol(Symbol::SimpleEscape(_)) => self.col += 2,
            Token::Symbol(Symbol::DecimalEscape(_)) => self.col += 4,
            Token::Newline => { self.line += 1; self.col = 1 }
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

