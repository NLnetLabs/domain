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

pub trait ScanWithOctets<O>: Sized {
    /// Scans a value with a scanner of a specific Octets type.
    fn scan_with_octets<S: Scanner<Octets = O>>(
        scanner: &mut S,
    ) -> Result<Self, S::Err>;
}

impl<X: Scan, O> ScanWithOctets<O> for X {
    fn scan_with_octets<S: Scanner<Octets = O>>(
        scanner: &mut S,
    ) -> Result<Self, S::Err> {
        Self::scan(scanner)
    }
}

pub trait Scanner {
    type Pos;
    type Err: From<(RdataError, Self::Pos)>;
    type Octets: AsRef<[u8]>;

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
        F: FnMut(&mut T, Symbol) -> Result<(), RdataError>,
        G: FnOnce(T) -> Result<U, RdataError>;

    /// Scans a word with Unicode text into a `String`.
    ///
    /// The method scans a word that consists of characters and puts these
    /// into a `String`. Once the word ends, the caller is given a chance
    /// to convert the value into something else via the closure `finalop`.
    /// This closure can fail, resulting in an error and back-tracking to
    /// the beginning of the phrase.
    fn scan_string_word<U, G>(&mut self, finalop: G) -> Result<U, Self::Err>
    where
        G: FnOnce(String) -> Result<U, RdataError>;

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
        F: FnMut(&mut T, Symbol) -> Result<(), RdataError>,
        G: FnOnce(T) -> Result<U, RdataError>;

    /// Scans a phrase with byte content into a `Bytes` value.
    ///
    /// The method scans a phrase that consists of byte only and puts these
    /// bytes into a `Bytes` value. Once the phrase ends, the caller is given
    /// a chance to convert the value into something else via the closure
    /// `finalop`. This closure can fail, resulting in an error and
    /// back-tracking to the beginning of the phrase.
    fn scan_byte_phrase<U, G>(&mut self, finalop: G) -> Result<U, Self::Err>
    where
        G: FnOnce(Self::Octets) -> Result<U, RdataError>;

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
        G: FnOnce(String) -> Result<U, RdataError>;

    /// Scans a domain name.
    fn scan_dname(&mut self) -> Result<Dname<Bytes>, Self::Err>;

    /// Scans a word containing a sequence of pairs of hex digits.
    ///
    /// The word is returned as a `Bytes` value with each byte representing
    /// the decoded value of one hex digit pair.
    fn scan_hex_word<U, G>(&mut self, finalop: G) -> Result<U, Self::Err>
    where
        G: FnOnce(Bytes) -> Result<U, RdataError>;

    fn scan_hex_words<U, G>(&mut self, finalop: G) -> Result<U, Self::Err>
    where
        G: FnOnce(Bytes) -> Result<U, RdataError>;

    /// Scans a phrase containing base32hex encoded data.
    ///
    /// In particular, this decodes the “base32hex” decoding definied in
    /// RFC 4648 without padding.
    fn scan_base32hex_phrase<U, G>(
        &mut self,
        finalop: G,
    ) -> Result<U, Self::Err>
    where
        G: FnOnce(Bytes) -> Result<U, RdataError>;

    /// Scans a sequence of phrases containing base64 encoded data.
    fn scan_base64_phrases<U, G>(
        &mut self,
        finalop: G,
    ) -> Result<U, Self::Err>
    where
        G: FnOnce(Bytes) -> Result<U, RdataError>;
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
                            return Err(RdataError::Unexpected(symbol));
                        }
                    }
                    _ => return Err(RdataError::Unexpected(symbol)),
                };
                *res = match res.checked_mul(10) {
                    Some(res) => res,
                    None => return Err(RdataError::IllegalInteger),
                };
                *res = match res.checked_add(ch) {
                    Some(res) => res,
                    None => return Err(RdataError::IllegalInteger),
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
                            return Err(RdataError::Unexpected(symbol));
                        }
                    }
                    _ => return Err(RdataError::Unexpected(symbol)),
                };
                *res = match res.checked_mul(10) {
                    Some(res) => res,
                    None => return Err(RdataError::IllegalInteger),
                };
                *res = match res.checked_add(ch) {
                    Some(res) => res,
                    None => return Err(RdataError::IllegalInteger),
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
                            return Err(RdataError::Unexpected(symbol));
                        }
                    }
                    _ => return Err(RdataError::Unexpected(symbol)),
                };
                *res = match res.checked_mul(10) {
                    Some(res) => res,
                    None => return Err(RdataError::IllegalInteger),
                };
                *res = match res.checked_add(ch) {
                    Some(res) => res,
                    None => return Err(RdataError::IllegalInteger),
                };
                Ok(())
            },
            Ok,
        )
    }
}

//============ Error Types ===================================================

//------------ SyntaxError ---------------------------------------------------

/// A syntax error happened while scanning record data.
#[derive(Debug)]
#[non_exhaustive]
pub enum RdataError {
    Expected(String),
    IllegalInteger, // TODO Add kind
    IllegalAddr(AddrParseError),
    IllegalName(name::FromStrError),
    LongCharStr,
    UnevenHexString,
    LongGenericData,
    RelativeName,
    Unexpected(Symbol),
    UnknownMnemonic,
    ///
    /// Used when converting some other content fails.
    Content(Box<dyn error::Error>),
}

impl RdataError {
    pub fn content<E: error::Error + 'static>(err: E) -> Self {
        RdataError::Content(Box::new(err))
    }
}

//--- From

impl From<BadSymbol> for RdataError {
    fn from(err: BadSymbol) -> RdataError {
        RdataError::Unexpected(err.0)
    }
}

impl From<AddrParseError> for RdataError {
    fn from(err: AddrParseError) -> RdataError {
        RdataError::IllegalAddr(err)
    }
}

impl From<name::FromStrError> for RdataError {
    fn from(err: name::FromStrError) -> RdataError {
        RdataError::IllegalName(err)
    }
}

impl From<name::PushNameError> for RdataError {
    fn from(err: name::PushNameError) -> RdataError {
        RdataError::from(name::FromStrError::from(err))
    }
}

//--- Display and Error

impl fmt::Display for RdataError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RdataError::Expected(ref s) => write!(f, "expected '{}'", s),
            RdataError::IllegalInteger => f.write_str("illegal integer"),
            RdataError::IllegalAddr(ref err) => {
                write!(f, "illegal address: {}", err)
            }
            RdataError::IllegalName(ref err) => {
                write!(f, "illegal domain name: {}", err)
            }
            RdataError::LongCharStr => {
                f.write_str("character string too long")
            }
            RdataError::UnevenHexString => {
                f.write_str("hex string with an odd number of characters")
            }
            RdataError::LongGenericData => {
                f.write_str("more data given than in the length byte")
            }
            RdataError::RelativeName => f.write_str("relative domain name"),
            RdataError::Unexpected(sym) => write!(f, "unexpected '{}'", sym),
            RdataError::UnknownMnemonic => f.write_str("unexpected mnemomic"),
            RdataError::Content(ref content) => content.fmt(f),
        }
    }
}

impl error::Error for RdataError {}
