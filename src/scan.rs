//! Deserialization of records.
#![cfg(feature = "scan")]
#![cfg_attr(docsrs, doc(cfg(feature = "scan")))]

use crate::base::name;
use crate::base::net::AddrParseError;
use crate::base::str::{BadSymbol, Symbol};
pub use crate::master::scan::ScanError;
use crate::master::scan::{CharSource, Scanner};
use std::boxed::Box;
use std::error;
use std::fmt;
use std::string::String;

//------------ Scan ----------------------------------------------------------

/// A type that can by scanned from a master file.
#[cfg(feature = "bytes")]
pub trait Scan: Sized {
    /// Scans a value from a master file.
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>,
    ) -> Result<Self, ScanError>;
}

#[cfg(feature = "bytes")]
impl Scan for u32 {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>,
    ) -> Result<Self, ScanError> {
        scanner.scan_phrase(
            0u32,
            |res, symbol| {
                let ch = match symbol {
                    Symbol::Char(ch) => {
                        if let Some(value) = ch.to_digit(10) {
                            value
                        } else {
                            return Err(SyntaxError::Unexpected(symbol));
                        }
                    }
                    _ => return Err(SyntaxError::Unexpected(symbol)),
                };
                *res = match res.checked_mul(10) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger),
                };
                *res = match res.checked_add(ch) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger),
                };
                Ok(())
            },
            Ok,
        )
    }
}

#[cfg(feature = "bytes")]
impl Scan for u16 {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>,
    ) -> Result<Self, ScanError> {
        scanner.scan_phrase(
            0u16,
            |res, symbol| {
                let ch = match symbol {
                    Symbol::Char(ch) => {
                        if let Some(value) = ch.to_digit(10) {
                            value as u16
                        } else {
                            return Err(SyntaxError::Unexpected(symbol));
                        }
                    }
                    _ => return Err(SyntaxError::Unexpected(symbol)),
                };
                *res = match res.checked_mul(10) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger),
                };
                *res = match res.checked_add(ch) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger),
                };
                Ok(())
            },
            Ok,
        )
    }
}

#[cfg(feature = "bytes")]
impl Scan for u8 {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>,
    ) -> Result<Self, ScanError> {
        scanner.scan_phrase(
            0u8,
            |res, symbol| {
                let ch = match symbol {
                    Symbol::Char(ch) => {
                        if let Some(value) = ch.to_digit(10) {
                            value as u8
                        } else {
                            return Err(SyntaxError::Unexpected(symbol));
                        }
                    }
                    _ => return Err(SyntaxError::Unexpected(symbol)),
                };
                *res = match res.checked_mul(10) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger),
                };
                *res = match res.checked_add(ch) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger),
                };
                Ok(())
            },
            Ok,
        )
    }
}

//============ Error Types ===================================================

//------------ SyntaxError ---------------------------------------------------

/// A syntax error happened while scanning master data.
#[derive(Debug)]
#[non_exhaustive]
pub enum SyntaxError {
    Expected(String),
    ExpectedNewline,
    ExpectedSpace,
    IllegalEscape,
    IllegalInteger, // TODO Add kind
    IllegalAddr(AddrParseError),
    IllegalName(name::FromStrError),
    LongCharStr,
    UnevenHexString,
    LongGenericData,
    NestedParentheses,
    NoDefaultTtl,
    NoLastClass,
    NoLastOwner,
    NoOrigin,
    RelativeName,
    Unexpected(Symbol),
    UnexpectedNewline,
    UnexpectedEof,
    UnknownMnemonic,
    ///
    /// Used when converting some other content fails.
    Content(Box<dyn error::Error>),
}

impl SyntaxError {
    pub fn content<E: error::Error + 'static>(err: E) -> Self {
        SyntaxError::Content(Box::new(err))
    }
}

//--- From

impl From<BadSymbol> for SyntaxError {
    fn from(err: BadSymbol) -> SyntaxError {
        SyntaxError::Unexpected(err.0)
    }
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

impl From<name::PushNameError> for SyntaxError {
    fn from(err: name::PushNameError) -> SyntaxError {
        SyntaxError::from(name::FromStrError::from(err))
    }
}

//--- Display and Error

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SyntaxError::Expected(ref s) => write!(f, "expected '{}'", s),
            SyntaxError::ExpectedNewline => {
                f.write_str("expected a new line")
            }
            SyntaxError::ExpectedSpace => f.write_str("expected white space"),
            SyntaxError::IllegalEscape => {
                f.write_str("invalid escape sequence")
            }
            SyntaxError::IllegalInteger => f.write_str("illegal integer"),
            SyntaxError::IllegalAddr(ref err) => {
                write!(f, "illegal address: {}", err)
            }
            SyntaxError::IllegalName(ref err) => {
                write!(f, "illegal domain name: {}", err)
            }
            SyntaxError::LongCharStr => {
                f.write_str("character string too long")
            }
            SyntaxError::UnevenHexString => {
                f.write_str("hex string with an odd number of characters")
            }
            SyntaxError::LongGenericData => {
                f.write_str("more data given than in the length byte")
            }
            SyntaxError::NestedParentheses => {
                f.write_str("nested parentheses")
            }
            SyntaxError::NoDefaultTtl => {
                f.write_str("omitted TTL but no default TTL given")
            }
            SyntaxError::NoLastClass => {
                f.write_str("omitted class but no previous class given")
            }
            SyntaxError::NoLastOwner => {
                f.write_str("omitted owner but no previous owner given")
            }
            SyntaxError::NoOrigin => {
                f.write_str("owner @ without preceding $ORIGIN")
            }
            SyntaxError::RelativeName => f.write_str("relative domain name"),
            SyntaxError::Unexpected(sym) => write!(f, "unexpected '{}'", sym),
            SyntaxError::UnexpectedNewline => {
                f.write_str("unexpected newline")
            }
            SyntaxError::UnexpectedEof => {
                f.write_str("unexpected end of file")
            }
            SyntaxError::UnknownMnemonic => {
                f.write_str("unexpected mnemomic")
            }
            SyntaxError::Content(ref content) => content.fmt(f),
        }
    }
}

impl error::Error for SyntaxError {}
