//! Deserialization of records.
#![cfg(feature = "scan")]
#![cfg_attr(docsrs, doc(cfg(feature = "scan")))]

use bytes::Bytes;
use name::Dname;

use crate::base::name;
use crate::base::net::AddrParseError;
use crate::base::str::{BadSymbol, Symbol};
use std::boxed::Box;
use std::error;
use std::fmt;
use std::string::String;

//------------ Scan ----------------------------------------------------------

/// A type that can by scanned from a master file.
#[cfg(feature = "bytes")]
pub trait Scan: Sized {
    /// Scans a value from a master file.
    fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Err>;
}

pub trait Scanner {
    type Pos;
    type Err: From<(SyntaxError, Self::Pos)>;

    /// Returns the current position of the scanner.
    fn pos(&self) -> Self::Pos;

    /// Skips over the word with the content `literal`.
    ///
    /// The content indeed needs to be literally the literal. Escapes are
    /// not translated before comparison and case has to be as is.
    fn skip_literal(&mut self, literal: &str) -> Result<(), Self::Err>;

    /// Scans a word token.
    ///
    /// A word is a sequence of non-special characters and escape sequences
    /// followed by a non-empty sequence of space unless it is followed
    /// directly by a [newline](#method.scan_newline). If successful, the
    /// method will position at the end of the space sequence if it is
    /// required. That is, you can scan for two subsequent word tokens
    /// without worrying about the space between them.
    ///
    /// The method starts out with a `target` value and two closures. The
    /// first closure, `symbolop`, is being fed symbols of the word one by one
    /// and should feed them into the target. Once the word ended, the
    /// second closure is called to convert the target into the final result.
    /// Both can error out at any time stopping processing and leading the
    /// scanner to revert to the beginning of the token.
    fn scan_word<T, U, F, G>(
        &mut self,
        target: T,
        symbolop: F,
        finalop: G,
    ) -> Result<U, Self::Err>
    where
        F: FnMut(&mut T, Symbol) -> Result<(), SyntaxError>,
        G: FnOnce(T) -> Result<U, SyntaxError>;

    /// Scans a word with Unicode text into a `String`.
    ///
    /// The method scans a word that consists of characters and puts these
    /// into a `String`. Once the word ends, the caller is given a chance
    /// to convert the value into something else via the closure `finalop`.
    /// This closure can fail, resulting in an error and back-tracking to
    /// the beginning of the phrase.
    fn scan_string_word<U, G>(&mut self, finalop: G) -> Result<U, Self::Err>
    where
        G: FnOnce(String) -> Result<U, SyntaxError>;

    /// Scans a phrase: a normal word or a quoted word.
    ///
    /// This method behaves like [scan_quoted()](#method.scan_quoted) if
    /// the next character is a double quote or like
    /// [scan_word()](#method.scan_word) otherwise.
    fn scan_phrase<T, U, F, G>(
        &mut self,
        target: T,
        symbolop: F,
        finalop: G,
    ) -> Result<U, Self::Err>
    where
        F: FnMut(&mut T, Symbol) -> Result<(), SyntaxError>,
        G: FnOnce(T) -> Result<U, SyntaxError>;

    /// Scans a phrase with byte content into a `Bytes` value.
    ///
    /// The method scans a phrase that consists of byte only and puts these
    /// bytes into a `Bytes` value. Once the phrase ends, the caller is given
    /// a chance to convert the value into something else via the closure
    /// `finalop`. This closure can fail, resulting in an error and
    /// back-tracking to the beginning of the phrase.
    fn scan_byte_phrase<U, G>(&mut self, finalop: G) -> Result<U, Self::Err>
    where
        G: FnOnce(Bytes) -> Result<U, SyntaxError>;

    /// Scans a phrase with Unicode text into a `String`.
    ///
    /// The method scans a phrase that consists of characters and puts these
    /// into a `String`. Once the phrase ends, the caller is given
    /// a chance to convert the value into something else via the closure
    /// `finalop`. This closure can fail, resulting in an error and
    /// back-tracking to the beginning of the phrase.
    fn scan_string_phrase<U, G>(
        &mut self,
        finalop: G,
    ) -> Result<U, Self::Err>
    where
        G: FnOnce(String) -> Result<U, SyntaxError>;

    /// Scans a domain name.
    fn scan_dname(&mut self) -> Result<Dname<Bytes>, Self::Err>;

    /// Scans a word containing a sequence of pairs of hex digits.
    ///
    /// The word is returned as a `Bytes` value with each byte representing
    /// the decoded value of one hex digit pair.
    fn scan_hex_word<U, G>(&mut self, finalop: G) -> Result<U, Self::Err>
    where
        G: FnOnce(Bytes) -> Result<U, SyntaxError>;

    fn scan_hex_words<U, G>(&mut self, finalop: G) -> Result<U, Self::Err>
    where
        G: FnOnce(Bytes) -> Result<U, SyntaxError>;

    /// Scans a phrase containing base32hex encoded data.
    ///
    /// In particular, this decodes the “base32hex” decoding definied in
    /// RFC 4648 without padding.
    fn scan_base32hex_phrase<U, G>(
        &mut self,
        finalop: G,
    ) -> Result<U, Self::Err>
    where
        G: FnOnce(Bytes) -> Result<U, SyntaxError>;

    /// Scans a sequence of phrases containing base64 encoded data.
    fn scan_base64_phrases<U, G>(
        &mut self,
        finalop: G,
    ) -> Result<U, Self::Err>
    where
        G: FnOnce(Bytes) -> Result<U, SyntaxError>;
}

#[cfg(feature = "bytes")]
impl Scan for u32 {
    fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Err> {
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
    fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Err> {
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
    fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Err> {
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
