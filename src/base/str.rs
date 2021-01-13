//! Support for converting from and to strings.
//!
//! This module contains helper types for converting from and to string
//! representation of types.

use core::fmt;
use super::octets::ParseError;


//------------ Symbol --------------------------------------------------------

/// The master file representation of a single character.
///
/// This is either a regular character or an escape sequence. See the variants
/// for more details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Symbol {
    /// An unescaped Unicode character.
    Char(char),

    /// A character escaped via a preceding backslash.
    SimpleEscape(char),

    /// A raw octet escaped using the decimal escape sequence.
    ///
    /// This escape sequence consists of a backslash followed by exactly three
    /// decimal digits with the value of the octets.
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

    /// Provides the best symbol for an octet.
    ///
    /// The function will use the simple escape sequence for octet values that
    /// represent ASCII spaces, quotes, backslashes, and semicolons and the
    /// plain ASCII value for all other printable ASCII characters. Any other
    /// value is escaped using the decimal escape sequence.
    pub fn from_octet(ch: u8) -> Self {
        if ch == b' ' || ch == b'"' || ch == b'\\' || ch == b';' {
            Symbol::SimpleEscape(ch as char)
        }
        else if !(0x20..=0x7E).contains(&ch) {
            Symbol::DecimalEscape(ch)
        }
        else {
            Symbol::Char(ch as char)
        }
    }

    /// Converts the symbol into an octet if it represents one.
    ///
    /// Both domain names and character strings operate on bytes instead of
    /// (Unicode) characters. These bytes can be represented by printable
    /// ASCII characters (that is, U+0020 to U+007E), both plain or through
    /// a simple escape, or by a decimal escape.
    ///
    /// This method returns such an octet or an error if the symbol doesn’t
    /// have value representing an octet. Note that it will succeed for an
    /// ASCII space character U+0020 which may be used as a word separator
    /// in some cases.
    pub fn into_octet(self) -> Result<u8, BadSymbol> {
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
    ///
    /// This will fail for a decimal escape sequence which doesn’t actually
    /// represent a character.
    pub fn into_char(self) -> Result<char, BadSymbol> {
        match self {
            Symbol::Char(ch) | Symbol::SimpleEscape(ch) => Ok(ch),
            Symbol::DecimalEscape(_) => Err(BadSymbol(self))
        }
    }

    /// Converts the symbol representing a digit into its integer value.
    pub fn into_digit(self, base: u32) -> Result<u32, BadSymbol> {
        if let Symbol::Char(ch) = self {
            match ch.to_digit(base) {
                Some(ch) => Ok(ch),
                None => Err(BadSymbol(self))
            }
        }
        else {
            Err(BadSymbol(self))
        }
    }

    /// Returns whether the symbol can occur as part of a word.
    ///
    /// This is true apart for unescaped ASCII space and horizontal tabs,
    /// opening and closing parantheses, the semicolon, and double quote.
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


//============ Error Types ===================================================

//------------ SymbolError ---------------------------------------------------

/// An error happened when reading a symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolError {
    /// An illegal escape sequence was encountered.
    BadEscape,

    /// Unexpected end of input.
    ///
    /// This can only happen in a decimal escape sequence.
    ShortInput
}


//--- Display and Error

impl fmt::Display for SymbolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SymbolError::BadEscape
                => f.write_str("illegal escape sequence"),
            SymbolError::ShortInput
                => ParseError::ShortInput.fmt(f)
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SymbolError { }


//------------ BadSymbol -----------------------------------------------------

/// A symbol with an unexpected value was encountered. 
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BadSymbol(pub Symbol);


//--- Display and Error

impl fmt::Display for BadSymbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unexpected symbol '{}'", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BadSymbol { }

