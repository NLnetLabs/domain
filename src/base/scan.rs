//! Parsing of data from its representation format.

use core::{fmt, str};
use core::convert::{TryFrom, TryInto};
//use core::iter::Peekable;
#[cfg(feature = "std")] use std::error;
use crate::base::charstr::CharStr;
use crate::base::name::ToDname;
use crate::base::octets::{OctetsBuilder, ParseError, ShortBuf};
use crate::base::str::String;


//============ Scanning Traits ===============================================

//------------ Scan ---------------------------------------------------------

/// A type that can be scanned from its representation format.
pub trait Scan<S: Scanner>: Sized {
    fn scan(scanner: &mut S) -> Result<Self, S::Error>;
}

macro_rules! impl_scan_unsigned {
    ( $type:ident) => {
        impl<S: Scanner> Scan<S> for $type {
            fn scan(
                scanner: &mut S,
            ) -> Result<Self, S::Error> {
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
    }
}

impl_scan_unsigned!(u8);
impl_scan_unsigned!(u16);
impl_scan_unsigned!(u32);
impl_scan_unsigned!(u64);
impl_scan_unsigned!(u128);

//------------ Scanner -------------------------------------------------------

/// A type that can produce tokens of data in representation format.
pub trait Scanner {
    type Octets: AsRef<[u8]>;
    type OctetsBuilder:
        OctetsBuilder<Octets = Self::Octets> + AsRef<[u8]> + AsMut<[u8]>;
    type Dname: ToDname;
    type Error: ScannerError;

    /// Returns whether the next token is preceded by white space.
    fn has_space(&self) -> bool;

    /// Returns whether there are more tokens in the entry.
    ///
    /// This method takes a `&mut self` to allow implementations to peek on
    /// request.
    fn continues(&mut self) -> bool;

    /// Scans a token into a sequence of symbols.
    fn scan_symbols<F>(&mut self, op: F) -> Result<(), Self::Error>
    where F: FnMut(Symbol) -> Result<(), Self::Error>;

    /// Scans the remainder of the entry as symbols.
    fn scan_entry_symbols<F>(
        self, op: F
    ) -> Result<(), Self::Error>
    where F: FnMut(EntrySymbol) -> Result<(), Self::Error>;

    /// Converts the symbols of a token into an octets sequence.
    fn convert_token<C: ConvertSymbols<Symbol, Self::Error>>(
        &mut self, convert: C,
    ) -> Result<Self::Octets, Self::Error>;

    /// Converts the symbols of a token into an octets sequence.
    fn convert_entry<C: ConvertSymbols<EntrySymbol, Self::Error>>(
        &mut self, convert: C,
    ) -> Result<Self::Octets, Self::Error>;

    /// Scans a token into an octets sequence.
    fn scan_octets(&mut self) -> Result<Self::Octets, Self::Error>;

    /// Scans a token into a domain name.
    fn scan_dname(&mut self) -> Result<Self::Dname, Self::Error>;

    /// Scans a token into a character string.
    ///
    /// Note that character strings have a length limit.  If you want a
    /// sequence of indefinite length, use [`scan_octets`][Self::scan_octets]
    /// instead.
    fn scan_charstr(&mut self) -> Result<CharStr<Self::Octets>, Self::Error>;

    /// Scans a token as a UTF-8 string.
    fn scan_string(&mut self) -> Result<String<Self::Octets>, Self::Error>;

    /// Scans a sequence of character strings until the end of the entry.
    ///
    /// The returned octets will contain the sequence of character string in
    /// wire format.
    fn scan_charstr_entry(&mut self) -> Result<Self::Octets, Self::Error>;

    /// Returns an empty octets builder.
    ///
    /// This builder can be used to create octets sequences in cases where
    /// the other methods can’t be used.
    fn octets_builder(&mut self) -> Result<Self::OctetsBuilder, Self::Error>;

    /// Scans a token as a borrowed ASCII string.
    ///
    /// If the next token contains non-ascii characters, returns an error.
    fn scan_ascii_str<F, T>(&mut self, op: F) -> Result<T, Self::Error>
    where F: FnOnce(&str) -> Result<T, Self::Error>;
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
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{}", msg)
        )
    }

    fn end_of_entry() -> Self {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "unexpected end of entry"
        )
    }

    fn short_buf() -> Self {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            ShortBuf
        )
    }

    fn trailing_tokens() -> Self {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "trailing data"
        )
    }
}

//------------ ConvertSymbols ------------------------------------------------

pub trait ConvertSymbols<Sym, Error> {
    /// Processes the next symbol.
    ///
    /// The method may return data to be added to the output octets sequence.
    fn process_symbol(
        &mut self, symbol: Sym,
    ) -> Result<Option<&[u8]>, Error>;

    /// Process the end of token.
    ///
    /// The method may return data to be added to the output octets sequence.
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
    pub fn from_chars<C>(chars: C) -> Result<Option<Self>, SymbolCharsError>
    where
        C: IntoIterator<Item = char>,
    {
        use self::SymbolCharsError::*;

        let mut chars = chars.into_iter();
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
                        None => return Err(BadEscape),
                    },
                    None => return Err(ShortInput),
                };
                let ch3 = match chars.next() {
                    Some(ch) => match ch.to_digit(10) {
                        Some(ch) => ch,
                        None => return Err(BadEscape),
                    },
                    None => return Err(ShortInput),
                };
                let res = ch + ch2 + ch3;
                if res > 255 {
                    return Err(BadEscape);
                }
                Ok(Some(Symbol::DecimalEscape(res as u8)))
            }
            Some(ch) => {
                let ch = u8::try_from(ch).map_err(|_| BadEscape)?;
                if ch < 0x20 || ch > 0x7e {
                    Err(BadEscape)
                }
                else {
                    Ok(Some(Symbol::SimpleEscape(ch)))
                }
            }
            None => Err(ShortInput),
        }
    }

    /// Reads a symbol from the given position in an octets slice.
    ///
    /// Returns the symbol and the index of the end of the symbol in the
    /// slice.
    pub fn from_slice_index(
        octets: &[u8], pos: usize
    ) -> Result<Option<(Symbol, usize)>, SymbolOctetsError> {
        use self::SymbolOctetsError::*;

        let c1 = match octets.get(pos) {
            Some(c1) => *c1,
            None => return Ok(None)
        };
        let pos = pos + 1;

        if c1 == b'\\' {
            // Escape sequence

            // Get the next octet.
            let c2 = match octets.get(pos) {
                Some(c2) => *c2,
                None => return Err(ShortInput),
            };
            let pos = pos + 1;

            if c2.is_ascii_control() {
                // Only printable ASCII characters allowed.
                return Err(BadEscape)
            }
            else if !c2.is_ascii_digit() {
                // Simple escape.
                return Ok(Some((Symbol::SimpleEscape(c2.into()), pos)))
            }

            // Get two more octets.
            let c3 = match octets.get(pos) {
                Some(c) if c.is_ascii_digit() => *c,
                Some(_) => return Err(BadEscape),
                None => return Err(ShortInput),
            };
            let pos = pos + 1;
            let c4 = match octets.get(pos) {
                Some(c) if c.is_ascii_digit() => *c,
                Some(_) => return Err(BadEscape),
                None => return Err(ShortInput),
            };
            let pos = pos + 1;

            Ok(Some((
                Symbol::DecimalEscape(
                    u8::try_from(
                          (u32::from(c2 - b'0') * 100)
                        + (u32::from(c3 - b'0') * 10)
                        + (u32::from(c4 - b'0'))
                    ).map_err(|_| BadEscape)?.into()
                ),
                pos
            )))
        }
        else {
            // UTF-8 encoded character.
            //
            // Looks like there’s nothing in the standard library to help us
            // do this.

            // ASCII is single byte.
            if c1 < 128 {
                return Ok(Some((Symbol::Char(c1.into()), pos)))
            }

            // Second-to-left but must be 1.
            if c1 & 0b0100_0000 == 0 {
                return Err(BadUtf8);
            }

            // Get the next octet, check that it is valid.
            let c2 = match octets.get(pos) {
                Some(c2) => *c2,
                None => return Err(ShortInput),
            };
            let pos = pos + 1;
            if c2 & 0b1100_0000 != 0b1000_0000 {
                return Err(BadUtf8);
            }

            // If c1’s third-to-left bit is 0, we have the two octet case.
            if c1 & 0b0010_0000 == 0 {
                return Ok(Some((
                    Symbol::Char(
                        (
                               u32::from(c2 & 0b0011_1111)
                            | (u32::from(c1 & 0b0001_1111) << 6)
                        ).try_into().map_err(|_| BadUtf8)?
                    ),
                    pos
                )))
            }

            // Get the next octet, check that it is valid.
            let c3 = match octets.get(pos) {
                Some(c3) => *c3,
                None => return Err(ShortInput),
            };
            let pos = pos + 1;
            if c3 & 0b1100_0000 != 0b1000_0000 {
                return Err(BadUtf8);
            }

            // If c1’s fourth-to-left bit is 0, we have the three octet case.
            if c1 & 0b0001_0000 == 0 {
                return Ok(Some((
                    Symbol::Char(
                        (
                               u32::from(c3 & 0b0011_1111)
                            | (u32::from(c2 & 0b0011_1111) << 6)
                            | (u32::from(c1 & 0b0001_1111) << 12)
                        ).try_into().map_err(|_| BadUtf8)?
                    ),
                    pos
                )))
            }

            // Get the next octet, check that it is valid.
            let c4 = match octets.get(pos) {
                Some(c4) => *c4,
                None => return Err(ShortInput),
            };
            let pos = pos + 1;
            if c4 & 0b1100_0000 != 0b1000_0000 {
                return Err(BadUtf8);
            }

            Ok(Some((
                Symbol::Char(
                    (
                           u32::from(c4 & 0b0011_1111)
                        | (u32::from(c3 & 0b0011_1111) << 6)
                        | (u32::from(c2 & 0b0011_1111) << 12)
                        | (u32::from(c1 & 0b0000_1111) << 18)
                    ).try_into().map_err(|_| BadUtf8)?
                ),
                pos
            )))
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
                    Err(BadSymbol(self))
                }
            }
            Symbol::SimpleEscape(ch) | Symbol::DecimalEscape(ch) => Ok(ch),
        }
    }

    pub fn into_ascii(self) -> Result<u8, BadSymbol> {
        match self {
            Symbol::Char(ch) => {
                if ch.is_ascii() && ch >= '\u{20}' && ch <= '\u{7E}' {
                    Ok(ch as u8)
                }
                else {
                    Err(BadSymbol(self))
                }
            }
            Symbol::SimpleEscape(ch) | Symbol::DecimalEscape(ch) => {
                if ch >= 0x20 && ch <= 0x7E {
                    Ok(ch)
                }
                else {
                    Err(BadSymbol(self))
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
            _ => Err(BadSymbol(self)),
        }
    }

    /// Converts the symbol representing a digit into its integer value.
    pub fn into_digit(self, base: u32) -> Result<u32, BadSymbol> {
        if let Symbol::Char(ch) = self {
            match ch.to_digit(base) {
                Some(ch) => Ok(ch),
                None => Err(BadSymbol(self)),
            }
        } else {
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
            Symbol::SimpleEscape(ch) => write!(f, "\\{}", ch),
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

//============ Simple Scanner Impl ===========================================

/*
/// A scanner reading tokens from an iterator over strings.
///
/// This is a very simple scanner implementation that assumes each string
/// produced by an iterator is a token. White space within the string is
/// allowed, escape sequences are interpreted.
#[derive(Clone, Debug)]
pub struct IterScanner<'a, I: Iterator<Item = &'a str>> {
    iter: Peekable<I>,
    origin: Dname<Cow<[u8]>>,
}

impl<'a, I: Iterator<Item = &'a str>> IterScanner<'a, I> {
    /// Creates a new scanner using the given iterator.
    pub fn new(iter: I, origin: Dname<Cow<[u8]>>) -> Self {
        IterScanner { iter: iter.peekable(), origin, }
    }

    fn next_token(&mut self) -> Result<&'a str, &'static str> {
        self.iter.next().ok_or("end of entry")
    }
}

impl<'a, I: Iterator<Item = &'a str>> IterScanner<'a, I> {
    type Octets = Cow<[u8]>;
    type OctetsBuilder = Cow<[u8]>;
    type Dname = Dname<Cow<[u8]>>,
/*
    type Symbols = Symbols<str::Chars<'a>>;
    type EntrySymbols = EntrySymbols<'a>
*/
    fn has_space(&self) -> bool {
        true
    }

    fn continues(&mut self) -> bool {
        self.iter.peek().is_some()
    }

    fn scan_symbols(
        &mut self
    ) -> Result<Symbols<str::Chars<'a>>, &'static str> {
        self.next_token().map(|s| Symbols::new(s.chars()))
    }

    fn scan_entry_symbols(
        self
    ) -> Result<EntrySymbols<'a, Peekable<I>>, &'static str> {
        Ok(EntrySymbols::new(self.iter))
    }
}
*/


//------------ Symbols -------------------------------------------------------

/// An iterator over the symbols in a char sequence.
#[derive(Clone, Debug)]
pub struct Symbols<Chars> {
    /// The chars of the sequence.
    ///
    /// This is an option so we can fuse the iterator on error.
    chars: Option<Chars>,
}

impl<Chars> Symbols<Chars> {
    /// Creates a new symbols iterator atop a char iterator.
    pub fn new(chars: Chars) -> Self {
        Symbols { chars: Some(chars) }
    }
}

impl<Chars: Iterator<Item = char>> Iterator for Symbols<Chars> {
    type Item = Symbol;

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(res) = Symbol::from_chars(self.chars.as_mut()?) {
            return res;
        }
        self.chars = None;
        None
    }
}


//------------ EntrySymbols --------------------------------------------------

/// An iterator over the symbols in an iterator over strings.
#[derive(Debug)]
pub struct EntrySymbols<'a, I> {
    iter: I,
    current: Option<Symbols<str::Chars<'a>>>,
}

impl<'a, I: Iterator<Item = &'a str>> EntrySymbols<'a, I> {
    /*
    fn new(iter: I) -> Self {
        EntrySymbols { iter, current: None }
    }
    */
}

impl<'a, I: Iterator<Item = &'a str>> Iterator for EntrySymbols<'a, I> {
    type Item = EntrySymbol;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(sym) = self.current.as_mut().and_then(Iterator::next) {
            return Some(sym.into())
        }
        if let Some(current) = self.iter.next() {
            self.current = Some(Symbols::new(current.chars()));
            Some(EntrySymbol::EndOfToken)
        }
        else {
            None
        }
    }
}


//============ Error Types ===================================================

//------------ SymbolCharsError ----------------------------------------------

/// An error happened when reading a symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolCharsError {
    /// An illegal escape sequence was encountered.
    BadEscape,

    /// Unexpected end of input.
    ///
    /// This can only happen in a decimal escape sequence.
    ShortInput,
}

//--- Display and Error

impl fmt::Display for SymbolCharsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SymbolCharsError::BadEscape => {
                f.write_str("illegal escape sequence")
            },
            SymbolCharsError::ShortInput => ParseError::ShortInput.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SymbolCharsError {}

//------------ SymbolOctetsError ---------------------------------------------

/// An error happened when reading a symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolOctetsError {
    /// An illegal UTF-8 sequence was encountered.
    BadUtf8,

    /// An illegal escape sequence was encountered.
    BadEscape,

    /// Unexpected end of input.
    ///
    /// This can only happen in a decimal escape sequence.
    ShortInput,
}

//--- Display and Error

impl fmt::Display for SymbolOctetsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SymbolOctetsError::BadUtf8 => {
                f.write_str("illegal UTF-8 sequence")
            }
            SymbolOctetsError::BadEscape => {
                f.write_str("illegal escape sequence")
            }
            SymbolOctetsError::ShortInput => ParseError::ShortInput.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SymbolOctetsError {}

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
impl std::error::Error for BadSymbol {}

#[cfg(feature = "std")]
impl From<BadSymbol> for std::io::Error {
    fn from(err: BadSymbol) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, err)
    }
}


//------------ IterScannerError ----------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct IterScannerError(&'static str);



//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn symbol_from_slice_index() {
        let mut buf = [0u8; 4];
        for ch in '\0'..char::MAX {
            if ch == '\\' {
                continue
            }
            let slice = ch.encode_utf8(&mut buf).as_bytes();
            assert_eq!(
                Symbol::from_slice_index(slice, 0),
                Ok(Some((
                    Symbol::Char(ch),
                    ch.len_utf8()
                ))),
                "char '{}'", ch,
            );
        }

        for ch in '0' .. '\x7f' {
            if ch.is_ascii_digit() {
                continue;
            }
            assert_eq!(
                Symbol::from_slice_index(
                    format!("\\{}", ch).as_bytes(), 0
                ),
                Ok(Some((
                    Symbol::SimpleEscape(ch as u8),
                    2
                ))),
                "sequence \"\\{}\"", ch
            );

        }

        for ch in 0..256 {
            assert_eq!(
                Symbol::from_slice_index(
                    format!("\\{:03}", ch).as_bytes(), 0
                ),
                Ok(Some((
                    Symbol::DecimalEscape(ch as u8),
                    4
                ))),
                "sequence \"\\{:03}\"", ch
            );
        }
    }
}

