//! Converting from and to strings.

use core::fmt;
#[cfg(feature = "bytes")] use bytes::{BufMut, BytesMut};
use derive_more::Display;
#[cfg(feature = "master")] use crate::master::scan::SyntaxError;

//------------ Symbol --------------------------------------------------------

/// The master file representation of a single character.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Symbol {
    /// An unescaped Unicode character.
    Char(char),

    /// An escape character by simply being backslashed.
    SimpleEscape(char),

    /// An escaped character using the decimal escape sequence.
    DecimalEscape(u8),
}

impl Symbol {
    /// Reads a symbol from a character source.
    ///
    /// Returns the next symbol in the source, `Ok(None)` if the source has
    /// been exhausted, or an error if there wasn’t a valid symbol.
    pub fn from_chars<C>(chars: C) -> Result<Option<Self>, SymbolError>
                      where C: IntoIterator<Item=char> {
        let mut chars = chars.into_iter();
        let ch = match chars.next() {
            Some(ch) => ch,
            None => return Ok(None),
        };
        if ch != '\\' {
            return Ok(Some(Symbol::Char(ch)))
        }
        match chars.next() {
            Some(ch) if ch.is_digit(10) => {
                let ch = ch.to_digit(10).unwrap() * 100;
                let ch2 = match chars.next() {
                    Some(ch) => match ch.to_digit(10) {
                        Some(ch) => ch * 10,
                        None => return Err(SymbolError::BadEscape)
                    }
                    None => return Err(SymbolError::ShortInput)
                };
                let ch3 = match chars.next() {
                    Some(ch)  => match ch.to_digit(10) {
                        Some(ch) => ch,
                        None => return Err(SymbolError::BadEscape)
                    }
                    None => return Err(SymbolError::ShortInput)
                };
                let res = ch + ch2 + ch3;
                if res > 255 {
                    return Err(SymbolError::BadEscape)
                }
                Ok(Some(Symbol::DecimalEscape(res as u8)))
            }
            Some(ch) => Ok(Some(Symbol::SimpleEscape(ch))),
            None => Err(SymbolError::ShortInput)
        }
    }

    /// Provides the best symbol for a byte.
    ///
    /// The function will use simple escape sequences for spaces, quotes,
    /// backslashs, and semicolons. It will leave all other printable ASCII
    /// characters unescaped and decimal escape all remaining byte value.
    pub fn from_byte(ch: u8) -> Self {
        if ch == b' ' || ch == b'"' || ch == b'\\' || ch == b';' {
            Symbol::SimpleEscape(ch as char)
        }
        else if ch < 0x20 || ch > 0x7E {
            Symbol::DecimalEscape(ch)
        }
        else {
            Symbol::Char(ch as char)
        }
    }

    /// Converts the symbol into a byte if it represents one.
    ///
    /// Both domain names and character strings operate on bytes instead of
    /// (Unicode) characters. These bytes can be represented by printable
    /// ASCII characters (that is, U+0020 to U+007E), both plain or through
    /// a simple escape, or by a decimal escape.
    ///
    /// This method returns such a byte or an error otherwise. Note that it
    /// will succeed for an ASCII space character U+0020 which may be used
    /// as a word separator in some cases.
    pub fn into_byte(self) -> Result<u8, BadSymbol> {
        match self {
            Symbol::Char(ch) | Symbol::SimpleEscape(ch) => {
                if ch.is_ascii() && ch >= '\u{20}' && ch <= '\u{7E}' {
                    Ok(ch as u8)
                }
                else {
                    Err(BadSymbol(self))
                }
            }
            Symbol::DecimalEscape(ch) => Ok(ch),
        }
    }

    /// Converts the symbol into a `char`.
    pub fn into_char(self) -> Result<char, BadSymbol> {
        match self {
            Symbol::Char(ch) | Symbol::SimpleEscape(ch) => Ok(ch),
            Symbol::DecimalEscape(_) => Err(BadSymbol(self))
        }
    }

    /// Converts the symbol representing a digit into its integer value.
    #[cfg(feature = "master")]
    pub fn into_digit(self, base: u32) -> Result<u32, SyntaxError> {
        if let Symbol::Char(ch) = self {
            match ch.to_digit(base) {
                Some(ch) => Ok(ch),
                None => Err(SyntaxError::Unexpected(self))
            }
        }
        else {
            Err(SyntaxError::Unexpected(self))
        }
    }

    /// Pushes a symbol that is a byte to the end of a byte buffer.
    ///
    /// If the symbol is a byte as per the rules described in `into_byte`,
    /// it will be pushed to the end of `buf`, reserving additional space
    /// if there isn’t enough space remaining.
    #[cfg(feature="bytes")]
    pub fn push_to_buf(self, buf: &mut BytesMut) -> Result<(), BadSymbol> {
        self.into_byte().map(|ch| {
            if buf.remaining_mut() == 0 {
                buf.reserve(1);
            }
            buf.put_u8(ch)
        })
    }

    /// Returns whether the symbol can occur as part of a word.
    pub fn is_word_char(self) -> bool {
        match self {
            Symbol::Char(ch) => {
                ch != ' ' && ch != '\t' && ch != '(' && ch != ')' &&
                ch != ';' && ch != '"'
            }
            _ => true
        }
    }
}


//--- From

impl From<char> for Symbol {
    fn from(ch: char) -> Symbol {
        Symbol::Char(ch)
    }
}


//--- Display

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Symbol::Char(ch) => write!(f, "{}", ch),
            Symbol::SimpleEscape(ch) => write!(f, "\\{}", ch),
            Symbol::DecimalEscape(ch) => write!(f, "\\{:03}", ch),
        }
    }
}


//------------ SymbolError ---------------------------------------------------

/// An error happened when reading a symbol.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum SymbolError {
    #[display(fmt="illegal escape sequence")]
    BadEscape,

    #[display(fmt="unexpected end of input")]
    ShortInput
}

#[cfg(feature = "std")]
impl std::error::Error for SymbolError { }


//------------ BadSymbol -----------------------------------------------------

/// A symbol of unexepected value was encountered. 
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="bad symbol '{}'", _0)]
pub struct BadSymbol(pub Symbol);

#[cfg(feature = "std")]
impl std::error::Error for BadSymbol { }

