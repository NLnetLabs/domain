//! Parsing of data from its presentation format.
//!
//! This module provides the basic machinery to parse DNS data from its
//! standard textual representation, known as the presentation format or,
//! perhaps more commonly, zonefile format. To distinguish this process from
//! parsing data from its binary wire format, we call this process
//! _scanning._
//!
//! The module provides two important traits which should sound familiar to
//! anyone who has used Serde before: [`Scan`] and [`Scanner`]. A type that
//! knows how to create a value from its presentation format implements
//! [`Scan`]. It uses an implementation of the [`Scanner`] trait as the source
//! of data in presentation format.
//!
//! This module provides a simple scanner that uses a sequence of strings as
//! its source and can be used to, for instance, read record data from
//! command line arguments. A “proper” scanner is included in the
#![cfg_attr(feature = "zonefile", doc = "[zonefile][crate::zonefile]")]
#![cfg_attr(not(feature = "zonefile"), doc = "zonefile")]
//! module.
#![allow(clippy::manual_range_contains)] // Hard disagree.
#![allow(unused_imports)] // XXX

use crate::base::charstr::{CharStr, CharStrBuilder};
use crate::base::name::{Dname, ToDname};
use crate::base::wire::{Compose, Composer};
use core::convert::{TryFrom, TryInto};
use core::iter::Peekable;
use core::marker::PhantomData;
use core::{fmt, str};
use octseq::str::Str;
use octseq::{
    EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder, ShortBuf,
    Truncate,
};
#[cfg(feature = "std")]
use std::error;

use super::Ttl;

//============ Scanning Traits ===============================================

//------------ Scan ---------------------------------------------------------

/// An extension trait to add scanning to foreign types.
///
/// This trait is generic over the specific scanner, allowing types to limit
/// their implementation to a scanners with certain properties.
pub trait Scan<S: Scanner>: Sized {
    /// Reads a value from the provided scanner.
    ///
    /// An implementation should read as many tokens as it needs from the
    /// scanner. It can assume that they are all available – the scanner will
    /// produce an error if it runs out of tokens prematurely.
    ///
    /// The implementation does not need to keep reading until the end of
    /// tokens. It is the responsibility of the user to make sure there are
    /// no stray tokens at the end of an entry.
    ///
    /// Finally, if an implementation needs to read tokens until the end of
    /// the entry, it can use [`Scanner::continues`] to check if there are
    /// still tokens left.
    ///
    /// If an implementation encounters an error in the presentation data,
    /// it should report it using [`ScannerError::custom`] unless any of the
    /// other methods of [`ScannerError`] seem more appropriate.
    fn scan(scanner: &mut S) -> Result<Self, S::Error>;
}

macro_rules! impl_scan_unsigned {
    ( $type:ident) => {
        impl<S: Scanner> Scan<S> for $type {
            fn scan(scanner: &mut S) -> Result<Self, S::Error> {
                let mut res: $type = 0;
                scanner.scan_symbols(|ch| {
                    res = res.checked_mul(10).ok_or_else(|| {
                        S::Error::custom("decimal number overflow")
                    })?;
                    res += ch.into_digit(10).map_err(|_| {
                        S::Error::custom("expected decimal number")
                    })? as $type;
                    Ok(())
                })?;
                Ok(res)
            }
        }
    };
}

impl_scan_unsigned!(u8);
impl_scan_unsigned!(u16);
impl_scan_unsigned!(u32);
impl_scan_unsigned!(u64);
impl_scan_unsigned!(u128);

impl<S: Scanner> Scan<S> for Ttl {
    fn scan(scanner: &mut S) -> Result<Self, <S as Scanner>::Error> {
        let mut res: u32 = 0;
        scanner.scan_symbols(|ch| {
            res = res
                .checked_mul(10)
                .ok_or_else(|| S::Error::custom("decimal number overflow"))?;
            res += ch
                .into_digit(10)
                .map_err(|_| S::Error::custom("expected decimal number"))?;
            Ok(())
        })?;
        Ok(Ttl::from_secs(res))
    }
}

//------------ Scanner -------------------------------------------------------

/// A type that can produce tokens of data in presentation format.
///
/// The presentation format is a relatively simple text format that provides
/// a sequence of _entries_ each consisting of a sequence of _tokens._ An
/// implementation of the `Scanner` trait provides access to the tokens of a
/// single entry.
///
/// Most methods of the trait process a single token to the caller. Exceptions
/// are those methods suffixed with `_entry`, which process all the remaining
/// tokens of the entry. In addition, [`has_space`][Scanner::has_space]
/// reports whether the token was prefixed with white space (which is relevant
/// in some cases), and [`continues`][Scanner::continues] reports whether
/// there are more tokens in the entry. It it returns `false, all the other
/// token and entry methods will return an error. That is, calling these
/// methods assumes that the caller requires at least one more token.
///
/// Because an implementation may be able to optimize the process of
/// converting tokens into output data types, there are a number of methods
/// for different output. Each of these methods assumes that the next token
/// (or the remaining tokens in the entry) is required to contain the
/// presentation format of the given type and is should produce an error
/// if that is not the case.
///
/// This allows for instance to optimize the creation of domain names and
/// avoid copying around data in the most usual cases.
///
/// As a consequence, an implementation gets to choose how to return tokens.
/// This mostly concerns the octets types to be used, but also allows it to
/// creatively employing the [name::Chain](crate::base::name::Chain) type to
/// deal with a zone’s changing origin.
pub trait Scanner {
    /// The type of octet sequences returned by the scanner.
    type Octets: AsRef<[u8]>;

    /// The octets builder used internally and returned upon request.
    type OctetsBuilder: OctetsBuilder
        + AsRef<[u8]>
        + AsMut<[u8]>
        + Truncate
        + FreezeBuilder<Octets = Self::Octets>;

    /// The type of a domain name returned by the scanner.
    type Dname: ToDname;

    /// The error type of the scanner.
    type Error: ScannerError;

    /// Returns whether the next token is preceded by white space.
    fn has_space(&self) -> bool;

    /// Returns whether there are more tokens in the entry.
    ///
    /// This method takes a `&mut self` to allow implementations to peek on
    /// request.
    fn continues(&mut self) -> bool;

    /// Scans a token into a sequence of symbols.
    ///
    /// Each symbol is passed to the caller via the closure and can be
    /// processed there.
    fn scan_symbols<F>(&mut self, op: F) -> Result<(), Self::Error>
    where
        F: FnMut(Symbol) -> Result<(), Self::Error>;

    /// Scans the remainder of the entry as symbols.
    ///
    /// Each symbol is passed to the caller via the closure and can be
    /// processed there.
    fn scan_entry_symbols<F>(&mut self, op: F) -> Result<(), Self::Error>
    where
        F: FnMut(EntrySymbol) -> Result<(), Self::Error>;

    /// Converts the symbols of a token into an octets sequence.
    ///
    /// Each symbol is passed to the provided converter which can return
    /// octet slices to be used to construct the returned value. When the
    /// token is complete, the converter is called again to ask for any
    /// remaining data to be added.
    fn convert_token<C: ConvertSymbols<Symbol, Self::Error>>(
        &mut self,
        convert: C,
    ) -> Result<Self::Octets, Self::Error>;

    /// Converts the symbols of a token into an octets sequence.
    ///
    /// Each symbol is passed to the provided converter which can return
    /// octet slices to be used to construct the returned value. When the
    /// token is complete, the converter is called again to ask for any
    /// remaining data to be added.
    fn convert_entry<C: ConvertSymbols<EntrySymbol, Self::Error>>(
        &mut self,
        convert: C,
    ) -> Result<Self::Octets, Self::Error>;

    /// Scans a token into an octets sequence.
    ///
    /// The returned sequence has all symbols converted into their octets.
    /// It can be of any length.
    fn scan_octets(&mut self) -> Result<Self::Octets, Self::Error>;

    /// Scans a token as a borrowed ASCII string.
    ///
    /// If the next token contains non-ascii characters, returns an error.
    /// The string is given to the caller via the provided closure.
    fn scan_ascii_str<F, T>(&mut self, op: F) -> Result<T, Self::Error>
    where
        F: FnOnce(&str) -> Result<T, Self::Error>;

    /// Scans a token into a domain name.
    fn scan_dname(&mut self) -> Result<Self::Dname, Self::Error>;

    /// Scans a token into a character string.
    ///
    /// Note that character strings have a length limit.  If you want a
    /// sequence of indefinite length, use [`scan_octets`][Self::scan_octets]
    /// instead.
    fn scan_charstr(&mut self) -> Result<CharStr<Self::Octets>, Self::Error>;

    /// Scans a token as a UTF-8 string.
    fn scan_string(&mut self) -> Result<Str<Self::Octets>, Self::Error>;

    /// Scans a sequence of character strings until the end of the entry.
    ///
    /// The returned octets will contain the sequence of character strings in
    /// wire format.
    fn scan_charstr_entry(&mut self) -> Result<Self::Octets, Self::Error>;

    /// Scans an optional unknown rdata marker.
    ///
    /// If the next token is `\#`, i.e., an unquoted, escaped hash sign,
    /// consumes the token and returns `Ok(true)`. If the next token is
    /// anything else or if there is no next token, does nothing and returns
    /// `Ok(false)`. If there is an error, returns an error.
    fn scan_opt_unknown_marker(&mut self) -> Result<bool, Self::Error>;

    /// Returns an empty octets builder.
    ///
    /// This builder can be used to create octets sequences in cases where
    /// the other methods can’t be used.
    fn octets_builder(&mut self) -> Result<Self::OctetsBuilder, Self::Error>;
}

//------------ ScannerError --------------------------------------------------

macro_rules! declare_error_trait {
    (ScannerError: Sized $(+ $($supertrait:ident)::+)*) => {
        /// A type providing error information for a scanner.
        pub trait ScannerError: Sized $(+ $($supertrait)::+)* {
            /// Creates a new error wrapping a supplied error message.
            fn custom(msg: &'static str) -> Self;

            /// Creates an error when more tokens were expected in the entry.
            fn end_of_entry() -> Self;

            /// Creates an error when a octets buffer is too short.
            fn short_buf() -> Self;

            /// Creates an error when there are trailing tokens.
            fn trailing_tokens() -> Self;
        }
    }
}

#[cfg(feature = "std")]
declare_error_trait!(ScannerError: Sized + error::Error);

#[cfg(not(feature = "std"))]
declare_error_trait!(ScannerError: Sized + fmt::Debug + fmt::Display);

#[cfg(feature = "std")]
impl ScannerError for std::io::Error {
    fn custom(msg: &'static str) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, msg)
    }

    fn end_of_entry() -> Self {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "unexpected end of entry",
        )
    }

    fn short_buf() -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, ShortBuf)
    }

    fn trailing_tokens() -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, "trailing data")
    }
}

//------------ ConvertSymbols ------------------------------------------------

/// A type that helps convert the symbols in presentation format.
///
/// This trait is used by [`Scanner::convert_token`] with [`Symbol`]s and
/// [`Scanner::convert_entry`] with [`EntrySymbol]`s.
///
/// For each symbol, [`process_symbol`][Self::process_symbol] is called. When
/// the end of token or entry is reached, [`process_tail`][Self::process_tail]
/// is called, giving the implementer a chance to return any remaining data.
pub trait ConvertSymbols<Sym, Error> {
    /// Processes the next symbol.
    ///
    /// If the method returns some data, it will be appended to the output
    /// octets sequence.
    fn process_symbol(&mut self, symbol: Sym)
        -> Result<Option<&[u8]>, Error>;

    /// Process the end of token.
    ///
    /// If the method returns some data, it will be appended to the output
    /// octets sequence.
    fn process_tail(&mut self) -> Result<Option<&[u8]>, Error>;
}

//============ Zone file symbol ==============================================

//------------ Symbol --------------------------------------------------------

/// The zone file representation of a single character.
///
/// This is either a regular character or an escape sequence. See the variants
/// for more details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Symbol {
    /// An unescaped Unicode character.
    Char(char),

    /// A character escaped via a preceding backslash.
    ///
    /// This escape sequence is only allowed for printable ASCII characters.
    SimpleEscape(u8),

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
    pub fn from_chars<C: Iterator<Item = char>>(
        chars: &mut C,
    ) -> Result<Option<Self>, SymbolCharsError> {
        #[inline]
        fn bad_escape() -> SymbolCharsError {
            SymbolCharsError(SymbolCharsEnum::BadEscape)
        }

        #[inline]
        fn short_input() -> SymbolCharsError {
            SymbolCharsError(SymbolCharsEnum::ShortInput)
        }

        let ch = match chars.next() {
            Some(ch) => ch,
            None => return Ok(None),
        };
        if ch != '\\' {
            return Ok(Some(Symbol::Char(ch)));
        }
        match chars.next() {
            Some(ch) if ch.is_ascii_digit() => {
                let ch = ch.to_digit(10).unwrap() * 100;
                let ch2 = match chars.next() {
                    Some(ch) => match ch.to_digit(10) {
                        Some(ch) => ch * 10,
                        None => return Err(bad_escape()),
                    },
                    None => return Err(short_input()),
                };
                let ch3 = match chars.next() {
                    Some(ch) => match ch.to_digit(10) {
                        Some(ch) => ch,
                        None => return Err(bad_escape()),
                    },
                    None => return Err(short_input()),
                };
                let res = ch + ch2 + ch3;
                if res > 255 {
                    return Err(bad_escape());
                }
                Ok(Some(Symbol::DecimalEscape(res as u8)))
            }
            Some(ch) => {
                let ch = u8::try_from(ch).map_err(|_| bad_escape())?;
                if ch < 0x20 || ch > 0x7e {
                    Err(bad_escape())
                } else {
                    Ok(Some(Symbol::SimpleEscape(ch)))
                }
            }
            None => Err(short_input()),
        }
    }

    /// Reads a symbol from the given position in an octets slice.
    ///
    /// Returns the symbol and the index of the end of the symbol in the
    /// slice.
    pub fn from_slice_index(
        octets: &[u8],
        pos: usize,
    ) -> Result<Option<(Symbol, usize)>, SymbolOctetsError> {
        #[inline]
        fn bad_utf8() -> SymbolOctetsError {
            SymbolOctetsError(SymbolOctetsEnum::BadUtf8)
        }

        #[inline]
        fn bad_escape() -> SymbolOctetsError {
            SymbolOctetsError(SymbolOctetsEnum::BadEscape)
        }

        #[inline]
        fn short_input() -> SymbolOctetsError {
            SymbolOctetsError(SymbolOctetsEnum::ShortInput)
        }

        let c1 = match octets.get(pos) {
            Some(c1) => *c1,
            None => return Ok(None),
        };
        let pos = pos + 1;

        if c1 == b'\\' {
            // Escape sequence

            // Get the next octet.
            let c2 = match octets.get(pos) {
                Some(c2) => *c2,
                None => return Err(short_input()),
            };
            let pos = pos + 1;

            if c2.is_ascii_control() {
                // Only printable ASCII characters allowed.
                return Err(bad_escape());
            } else if !c2.is_ascii_digit() {
                // Simple escape.
                return Ok(Some((Symbol::SimpleEscape(c2), pos)));
            }

            // Get two more octets.
            let c3 = match octets.get(pos) {
                Some(c) if c.is_ascii_digit() => *c,
                Some(_) => return Err(bad_escape()),
                None => return Err(short_input()),
            };
            let pos = pos + 1;
            let c4 = match octets.get(pos) {
                Some(c) if c.is_ascii_digit() => *c,
                Some(_) => return Err(bad_escape()),
                None => return Err(short_input()),
            };
            let pos = pos + 1;

            Ok(Some((
                Symbol::DecimalEscape(
                    u8::try_from(
                        (u32::from(c2 - b'0') * 100)
                            + (u32::from(c3 - b'0') * 10)
                            + (u32::from(c4 - b'0')),
                    )
                    .map_err(|_| bad_escape())?,
                ),
                pos,
            )))
        } else {
            // UTF-8 encoded character.
            //
            // Looks like there’s nothing in the standard library to help us
            // do this.

            // ASCII is single byte.
            if c1 < 128 {
                return Ok(Some((Symbol::Char(c1.into()), pos)));
            }

            // Second-to-left but must be 1.
            if c1 & 0b0100_0000 == 0 {
                return Err(bad_utf8());
            }

            // Get the next octet, check that it is valid.
            let c2 = match octets.get(pos) {
                Some(c2) => *c2,
                None => return Err(short_input()),
            };
            let pos = pos + 1;
            if c2 & 0b1100_0000 != 0b1000_0000 {
                return Err(bad_utf8());
            }

            // If c1’s third-to-left bit is 0, we have the two octet case.
            if c1 & 0b0010_0000 == 0 {
                return Ok(Some((
                    Symbol::Char(
                        (u32::from(c2 & 0b0011_1111)
                            | (u32::from(c1 & 0b0001_1111) << 6))
                            .try_into()
                            .map_err(|_| bad_utf8())?,
                    ),
                    pos,
                )));
            }

            // Get the next octet, check that it is valid.
            let c3 = match octets.get(pos) {
                Some(c3) => *c3,
                None => return Err(short_input()),
            };
            let pos = pos + 1;
            if c3 & 0b1100_0000 != 0b1000_0000 {
                return Err(bad_utf8());
            }

            // If c1’s fourth-to-left bit is 0, we have the three octet case.
            if c1 & 0b0001_0000 == 0 {
                return Ok(Some((
                    Symbol::Char(
                        (u32::from(c3 & 0b0011_1111)
                            | (u32::from(c2 & 0b0011_1111) << 6)
                            | (u32::from(c1 & 0b0001_1111) << 12))
                            .try_into()
                            .map_err(|_| bad_utf8())?,
                    ),
                    pos,
                )));
            }

            // Get the next octet, check that it is valid.
            let c4 = match octets.get(pos) {
                Some(c4) => *c4,
                None => return Err(short_input()),
            };
            let pos = pos + 1;
            if c4 & 0b1100_0000 != 0b1000_0000 {
                return Err(bad_utf8());
            }

            Ok(Some((
                Symbol::Char(
                    (u32::from(c4 & 0b0011_1111)
                        | (u32::from(c3 & 0b0011_1111) << 6)
                        | (u32::from(c2 & 0b0011_1111) << 12)
                        | (u32::from(c1 & 0b0000_1111) << 18))
                        .try_into()
                        .map_err(|_| bad_utf8())?,
                ),
                pos,
            )))
        }
    }

    /// Provides the best symbol for an octet.
    ///
    /// The function will use the simple escape sequence for octet values that
    /// represent ASCII spaces, quotes, backslashes, and semicolons and the
    /// plain ASCII value for all other printable ASCII characters. Any other
    /// value is escaped using the decimal escape sequence.
    #[must_use]
    pub fn from_octet(ch: u8) -> Self {
        if ch == b' ' || ch == b'"' || ch == b'\\' || ch == b';' {
            Symbol::SimpleEscape(ch)
        } else if !(0x20..0x7F).contains(&ch) {
            Symbol::DecimalEscape(ch)
        } else {
            Symbol::Char(ch as char)
        }
    }

    /// Provides the best symbol for an octet inside a quoted string.
    ///
    /// The function will only escape a double quote and backslash using a
    /// simple escape and all non-printable characters using decimal escapes.
    #[must_use]
    pub fn quoted_from_octet(ch: u8) -> Self {
        if ch == b'"' || ch == b'\\' {
            Symbol::SimpleEscape(ch)
        } else if !(0x20..0x7F).contains(&ch) {
            Symbol::DecimalEscape(ch)
        } else {
            Symbol::Char(ch as char)
        }
    }

    /// Provides the best symbol for an octet inside a `Display` impl.
    ///
    /// The function will only escape a backslash using a simple escape and
    /// all non-printable characters using decimal escapes.
    #[must_use]
    pub fn display_from_octet(ch: u8) -> Self {
        if ch == b'\\' {
            Symbol::SimpleEscape(ch)
        } else if !(0x20..0x7F).contains(&ch) {
            Symbol::DecimalEscape(ch)
        } else {
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
            Symbol::Char(ch) => {
                if ch.is_ascii() && ch >= '\u{20}' && ch <= '\u{7E}' {
                    Ok(ch as u8)
                } else {
                    Err(BadSymbol(BadSymbolEnum::NonAscii))
                }
            }
            Symbol::SimpleEscape(ch) | Symbol::DecimalEscape(ch) => Ok(ch),
        }
    }

    /// Converts the symbol into an octet if it is printable ASCII.
    ///
    /// This is similar to [`into_octet`][Self::into_octet] but returns an
    /// error when the resulting octet is not a printable ASCII character,
    /// i.e., an octet of value 0x20 up to and including 0x7E.
    pub fn into_ascii(self) -> Result<u8, BadSymbol> {
        match self {
            Symbol::Char(ch) => {
                if ch.is_ascii() && ch >= '\u{20}' && ch <= '\u{7E}' {
                    Ok(ch as u8)
                } else {
                    Err(BadSymbol(BadSymbolEnum::NonAscii))
                }
            }
            Symbol::SimpleEscape(ch) | Symbol::DecimalEscape(ch) => {
                if ch >= 0x20 && ch <= 0x7E {
                    Ok(ch)
                } else {
                    Err(BadSymbol(BadSymbolEnum::NonAscii))
                }
            }
        }
    }

    /// Converts the symbol into a `char`.
    ///
    /// This will fail for a decimal escape sequence which doesn’t actually
    /// represent a character.
    pub fn into_char(self) -> Result<char, BadSymbol> {
        match self {
            Symbol::Char(ch) => Ok(ch),
            Symbol::SimpleEscape(ch) if ch >= 0x20 && ch < 0x7F => {
                Ok(ch.into())
            }
            _ => Err(BadSymbol(BadSymbolEnum::NonUtf8)),
        }
    }

    /// Converts the symbol representing a digit into its integer value.
    pub fn into_digit(self, base: u32) -> Result<u32, BadSymbol> {
        if let Symbol::Char(ch) = self {
            match ch.to_digit(base) {
                Some(ch) => Ok(ch),
                None => Err(BadSymbol(BadSymbolEnum::NonDigit)),
            }
        } else {
            Err(BadSymbol(BadSymbolEnum::Escape))
        }
    }

    /// Returns whether the symbol can occur as part of a word.
    ///
    /// This is true for all symbols other than unescaped ASCII space and
    /// horizontal tabs, opening and closing parentheses, semicolon, and
    /// double quote.
    #[must_use]
    pub fn is_word_char(self) -> bool {
        match self {
            Symbol::Char(ch) => {
                ch != ' '
                    && ch != '\t'
                    && ch != '\n'
                    && ch != '('
                    && ch != ')'
                    && ch != ';'
                    && ch != '"'
            }
            _ => true,
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
            Symbol::SimpleEscape(ch) => write!(f, "\\{}", ch as char),
            Symbol::DecimalEscape(ch) => write!(f, "\\{:03}", ch),
        }
    }
}

//------------ EntrySymbol ---------------------------------------------------

/// The symbols encountered in the remainder of an entry.
///
/// This can either be a regular symbol or the end of a token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntrySymbol {
    /// A regular in-token symbol.
    Symbol(Symbol),

    /// The end of a token.
    EndOfToken,
}

//--- From

impl From<Symbol> for EntrySymbol {
    fn from(symbol: Symbol) -> Self {
        EntrySymbol::Symbol(symbol)
    }
}

//------------ Symbols -------------------------------------------------------

/// An iterator over the symbols in a char sequence.
///
/// The iterator stops if a character cannot be converted into symbols. You
/// can check if that happened via the [`ok`][Self::ok] method.
#[derive(Clone, Debug)]
pub struct Symbols<Chars> {
    /// The chars of the sequence.
    ///
    /// This is an option so we can fuse the iterator on error.
    chars: Result<Chars, SymbolCharsError>,
}

impl<Chars> Symbols<Chars> {
    /// Creates a new symbols iterator atop a char iterator.
    pub fn new(chars: Chars) -> Self {
        Symbols { chars: Ok(chars) }
    }

    /// Checks whether there was an error converting symbols.
    pub fn ok(self) -> Result<(), SymbolCharsError> {
        self.chars.map(|_| ())
    }

    pub fn with<F, T, E>(chars: Chars, op: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
        E: From<SymbolCharsError>,
    {
        let mut symbols = Self::new(chars);
        let res = op(&mut symbols)?;
        symbols.ok()?;
        Ok(res)
    }
}

impl<Chars: Iterator<Item = char>> Iterator for Symbols<Chars> {
    type Item = Symbol;

    fn next(&mut self) -> Option<Self::Item> {
        self.chars = {
            let chars = match self.chars.as_mut() {
                Ok(chars) => chars,
                Err(_) => return None,
            };
            match Symbol::from_chars(chars) {
                Ok(res) => return res,
                Err(err) => Err(err),
            }
        };
        None
    }
}

//------------ IterScanner ---------------------------------------------------

/// A simple scanner atop an iterator of strings.
///
/// The type is generic over the iterator as well as the octets sequence to
/// use for returned data. The types associated octets builder is used to
/// create values.
pub struct IterScanner<Iter: Iterator, Octets> {
    /// The source of tokens of the scanner.
    iter: Peekable<Iter>,

    /// The marker for the output octets sequence type.
    marker: PhantomData<Octets>,
}

impl<Iter: Iterator, Octets> IterScanner<Iter, Octets> {
    /// Creates a new scanner from an iterator.
    pub fn new<I: IntoIterator<IntoIter = Iter>>(iter: I) -> Self {
        IterScanner {
            iter: iter.into_iter().peekable(),
            marker: PhantomData,
        }
    }

    /// Returns whether the iterator is exhausted.
    pub fn is_exhausted(&mut self) -> bool {
        self.iter.peek().is_none()
    }
}

impl<Iter, Item, Octets> Scanner for IterScanner<Iter, Octets>
where
    Item: AsRef<str>,
    Iter: Iterator<Item = Item>,
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder: EmptyBuilder + Composer,
{
    type Octets = Octets;
    type OctetsBuilder = <Octets as FromBuilder>::Builder;
    type Dname = Dname<Octets>;
    type Error = StrError;

    fn has_space(&self) -> bool {
        false
    }

    fn continues(&mut self) -> bool {
        self.iter.peek().is_some()
    }

    fn scan_symbols<F>(&mut self, mut op: F) -> Result<(), Self::Error>
    where
        F: FnMut(Symbol) -> Result<(), Self::Error>,
    {
        let token = match self.iter.next() {
            Some(token) => token,
            None => return Err(StrError::end_of_entry()),
        };
        for sym in Symbols::new(token.as_ref().chars()) {
            op(sym)?;
        }
        Ok(())
    }

    fn scan_entry_symbols<F>(&mut self, mut op: F) -> Result<(), Self::Error>
    where
        F: FnMut(EntrySymbol) -> Result<(), Self::Error>,
    {
        for token in &mut self.iter {
            for sym in Symbols::new(token.as_ref().chars()) {
                op(sym.into())?;
            }
            op(EntrySymbol::EndOfToken)?;
        }
        Ok(())
    }

    fn convert_token<C: ConvertSymbols<Symbol, Self::Error>>(
        &mut self,
        mut convert: C,
    ) -> Result<Self::Octets, Self::Error> {
        let token = match self.iter.next() {
            Some(token) => token,
            None => return Err(StrError::end_of_entry()),
        };
        let mut res = <Octets as FromBuilder>::Builder::empty();

        for sym in Symbols::new(token.as_ref().chars()) {
            if let Some(data) = convert.process_symbol(sym)? {
                res.append_slice(data).map_err(Into::into)?;
            }
        }

        if let Some(data) = convert.process_tail()? {
            res.append_slice(data).map_err(Into::into)?;
        }

        Ok(<Octets as FromBuilder>::from_builder(res))
    }

    fn convert_entry<C: ConvertSymbols<EntrySymbol, Self::Error>>(
        &mut self,
        mut convert: C,
    ) -> Result<Self::Octets, Self::Error> {
        let mut res = <Octets as FromBuilder>::Builder::empty();
        for token in &mut self.iter {
            for sym in Symbols::new(token.as_ref().chars()) {
                if let Some(data) = convert.process_symbol(sym.into())? {
                    res.append_slice(data).map_err(Into::into)?;
                }
            }
        }
        if let Some(data) = convert.process_tail()? {
            res.append_slice(data).map_err(Into::into)?;
        }
        Ok(<Octets as FromBuilder>::from_builder(res))
    }

    fn scan_octets(&mut self) -> Result<Self::Octets, Self::Error> {
        let token = match self.iter.next() {
            Some(token) => token,
            None => return Err(StrError::end_of_entry()),
        };
        let mut res = <Octets as FromBuilder>::Builder::empty();
        for sym in Symbols::new(token.as_ref().chars()) {
            match sym.into_octet() {
                Ok(ch) => res.append_slice(&[ch]).map_err(Into::into)?,
                Err(_) => return Err(StrError::custom("bad symbol")),
            }
        }
        Ok(<Octets as FromBuilder>::from_builder(res))
    }

    fn scan_ascii_str<F, T>(&mut self, op: F) -> Result<T, Self::Error>
    where
        F: FnOnce(&str) -> Result<T, Self::Error>,
    {
        let res = self.scan_string()?;
        if res.is_ascii() {
            op(&res)
        } else {
            Err(StrError::custom("non-ASCII characters"))
        }
    }

    fn scan_dname(&mut self) -> Result<Self::Dname, Self::Error> {
        let token = match self.iter.next() {
            Some(token) => token,
            None => return Err(StrError::end_of_entry()),
        };
        Dname::from_symbols(Symbols::new(token.as_ref().chars()))
            .map_err(|_| StrError::custom("invalid domain name"))
    }

    fn scan_charstr(&mut self) -> Result<CharStr<Self::Octets>, Self::Error> {
        let token = match self.iter.next() {
            Some(token) => token,
            None => return Err(StrError::end_of_entry()),
        };
        let mut res =
            CharStrBuilder::<<Octets as FromBuilder>::Builder>::new();
        for sym in Symbols::new(token.as_ref().chars()) {
            match sym.into_octet() {
                Ok(ch) => res.append_slice(&[ch])?,
                Err(_) => return Err(StrError::custom("bad symbol")),
            }
        }
        Ok(res.finish())
    }

    fn scan_string(&mut self) -> Result<Str<Self::Octets>, Self::Error> {
        let token = match self.iter.next() {
            Some(token) => token,
            None => return Err(StrError::end_of_entry()),
        };
        let mut res = <Octets as FromBuilder>::Builder::empty();
        let mut buf = [0u8; 4];
        for sym in Symbols::new(token.as_ref().chars()) {
            match sym.into_char() {
                Ok(ch) => res
                    .append_slice(ch.encode_utf8(&mut buf).as_bytes())
                    .map_err(Into::into)?,
                Err(_) => return Err(StrError::custom("bad symbol")),
            }
        }
        Ok(Str::from_utf8(<Octets as FromBuilder>::from_builder(res))
            .unwrap())
    }

    fn scan_charstr_entry(&mut self) -> Result<Self::Octets, Self::Error> {
        // XXX This implementation is probably a bit too lazy.
        let mut res = <Octets as FromBuilder>::Builder::empty();
        while self.iter.peek().is_some() {
            self.scan_charstr()?.compose(&mut res).map_err(Into::into)?;
        }
        Ok(<Octets as FromBuilder>::from_builder(res))
    }

    fn scan_opt_unknown_marker(&mut self) -> Result<bool, Self::Error> {
        match self.iter.peek() {
            Some(token) if token.as_ref() == "\\#" => Ok(true),
            _ => Ok(false),
        }
    }

    fn octets_builder(&mut self) -> Result<Self::OctetsBuilder, Self::Error> {
        Ok(<Octets as FromBuilder>::Builder::empty())
    }
}

//============ Error Types ===================================================

//------------ SymbolCharsError ----------------------------------------------

/// An error happened when reading a symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolCharsError(SymbolCharsEnum);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SymbolCharsEnum {
    /// An illegal escape sequence was encountered.
    BadEscape,

    /// Unexpected end of input.
    ///
    /// This can only happen in a decimal escape sequence.
    ShortInput,
}

impl SymbolCharsError {
    /// Creates a “bad escape” variant of the error.
    pub(crate) const fn bad_escape() -> Self {
        Self(SymbolCharsEnum::BadEscape)
    }

    /// Creates a “short input” variant of the error.
    pub(crate) const fn short_input() -> Self {
        Self(SymbolCharsEnum::ShortInput)
    }

    /// Returns a static description of the error.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self.0 {
            SymbolCharsEnum::BadEscape => "illegal escape sequence",
            SymbolCharsEnum::ShortInput => "unexpected end of input",
        }
    }
}

//--- Display and Error

impl fmt::Display for SymbolCharsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SymbolCharsError {}

//------------ SymbolOctetsError ---------------------------------------------

/// An error happened when reading a symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolOctetsError(SymbolOctetsEnum);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SymbolOctetsEnum {
    /// An illegal UTF-8 sequence was encountered.
    BadUtf8,

    /// An illegal escape sequence was encountered.
    BadEscape,

    /// Unexpected end of input.
    ///
    /// This can only happen in a decimal escape sequence.
    ShortInput,
}

impl SymbolOctetsError {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self.0 {
            SymbolOctetsEnum::BadUtf8 => "illegal UTF-8 sequence",
            SymbolOctetsEnum::BadEscape => "illegal escape sequence",
            SymbolOctetsEnum::ShortInput => "unexpected end of data",
        }
    }
}

//--- Display and Error

impl fmt::Display for SymbolOctetsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SymbolOctetsError {}

//------------ BadSymbol -----------------------------------------------------

/// A symbol with an unexpected value was encountered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BadSymbol(BadSymbolEnum);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BadSymbolEnum {
    /// A non-ASCII character was encountered.
    NonAscii,

    /// A non-UTF8 character was encountered.
    NonUtf8,

    /// A non-digit character was encountered.
    NonDigit,

    /// An unexpected escape sequence was encountered.
    Escape,
}

impl BadSymbol {
    pub(crate) fn non_ascii() -> Self {
        Self(BadSymbolEnum::NonAscii)
    }

    /// Returns a static description of the error.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self.0 {
            BadSymbolEnum::NonAscii => "non-ASCII symbol",
            BadSymbolEnum::NonUtf8 => "invalid UTF-8 sequence",
            BadSymbolEnum::NonDigit => "expected digit",
            BadSymbolEnum::Escape => "unexpected escape sequence",
        }
    }
}

//--- Display and Error

impl fmt::Display for BadSymbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BadSymbol {}

#[cfg(feature = "std")]
impl From<BadSymbol> for std::io::Error {
    fn from(err: BadSymbol) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, err)
    }
}

//------------ StrError ------------------------------------------------------

/// A simple scanner error that just wraps a static str.
#[derive(Debug)]
pub struct StrError(&'static str);

impl ScannerError for StrError {
    fn custom(msg: &'static str) -> Self {
        StrError(msg)
    }

    fn end_of_entry() -> Self {
        Self::custom("unexpected end of entry")
    }

    fn short_buf() -> Self {
        Self::custom("short buffer")
    }

    fn trailing_tokens() -> Self {
        Self::custom("trailing data")
    }
}

impl From<ShortBuf> for StrError {
    fn from(_: ShortBuf) -> Self {
        Self::short_buf()
    }
}

impl fmt::Display for StrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StrError {}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;

    #[test]
    fn symbol_from_slice_index() {
        let mut buf = [0u8; 4];
        for ch in '\0'..char::MAX {
            if ch == '\\' {
                continue;
            }
            let slice = ch.encode_utf8(&mut buf).as_bytes();
            assert_eq!(
                Symbol::from_slice_index(slice, 0),
                Ok(Some((Symbol::Char(ch), ch.len_utf8()))),
                "char '{}'",
                ch,
            );
        }

        for ch in '0'..'\x7f' {
            if ch.is_ascii_digit() {
                continue;
            }
            assert_eq!(
                Symbol::from_slice_index(format!("\\{}", ch).as_bytes(), 0),
                Ok(Some((Symbol::SimpleEscape(ch as u8), 2))),
                "sequence \"\\{}\"",
                ch
            );
        }

        for ch in 0..256 {
            assert_eq!(
                Symbol::from_slice_index(
                    format!("\\{:03}", ch).as_bytes(),
                    0
                ),
                Ok(Some((Symbol::DecimalEscape(ch as u8), 4))),
                "sequence \"\\{:03}\"",
                ch
            );
        }
    }
}
