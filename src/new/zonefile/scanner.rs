//! Scanning the data in a zonefile entry.
//!
//! Following the [specification] used by this implementation, a zone file is
//! a sequence of entries.  The syntax for a zonefile entry is fairly diverse,
//! and can grow over time (as new record data types are added); rather than
//! trying to parse every possible syntax, this low-level module provides the
//! tools to parse a zonefile entry in any format.
//!
//! [specification]: super#specification
//!
//! ## Usage
//!
// TODO
//!

use core::{fmt, num::IntErrorKind};
use std::vec::Vec;

use bumpalo::Bump;

use crate::new::base::name::RevName;

//----------- Scanner --------------------------------------------------------

/// A scanner for parsing a single zonefile entry.
#[derive(Clone, Debug)]
pub struct Scanner<'a> {
    /// The remaining data in the entry.
    remaining: &'a [u8],

    /// The origin for relative domain names.
    origin: Option<&'a RevName>,
}

//--- Construction

impl<'a> Scanner<'a> {
    /// Prepare to scan a zonefile entry.
    ///
    /// The input is a byte string representing the zonefile entry.  It should
    /// primarily consist of ASCII text.  It may span multiple lines.  Any
    /// comments (whose grammar is defined in the [specification]) should be
    /// stripped out beforehand.
    ///
    /// [specification]: super#specification
    ///
    /// The provided origin name (if any) is used to resolve relative domain
    /// names within the entry.  If the scanner requires an origin name (e.g.
    /// because the entry contained a relative domain name) but one is not
    /// provided, an error will occur.
    pub fn new(entry: &'a [u8], origin: Option<&'a RevName>) -> Self {
        Self {
            remaining: entry,
            origin,
        }
    }
}

//--- Inspection

impl<'a> Scanner<'a> {
    /// The remaining content in the entry.
    pub fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    /// Whether the scanner has been emptied.
    pub fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    /// The origin for relative domain names.
    pub fn origin(&self) -> Option<&'a RevName> {
        self.origin
    }
}

//--- Interaction

impl<'a> Scanner<'a> {
    /// Parse a plain token, without quotes and escapes.
    ///
    /// The following grammar is parsed:
    ///
    /// ```text
    /// plain-token = [^"\\\(\); \t\r\n]+
    /// ```
    pub fn scan_plain_token(&mut self) -> Result<&'a str, ScanError> {
        let (chunk, first) = self.scan_unquoted_chunk(|_| false);

        match first {
            Some(b' ' | b'\t' | b'\r' | b'\n') | None => {}
            Some(b'"') => return Err(ScanError::ProhibitedQuote),
            Some(b'\\') => return Err(ScanError::ProhibitedEscape),
            Some(_) => return Err(ScanError::InvalidCharacter),
        }

        if chunk.is_empty() {
            return Err(ScanError::Incomplete);
        }

        // SAFETY: Only ASCII characters were allowed in the string.
        Ok(unsafe { core::str::from_utf8_unchecked(chunk) })
    }

    /// Parse a conventional token into the given buffer.
    ///
    /// The following grammar is parsed:
    ///
    /// ```text
    /// token = ([^"\\\(\); \t\r\n] | "\\" escape | quoted-string)+
    /// escape = (ascii-printable & [^0-9]) | [0-9][0-9][0-9]
    /// quoted-string = '"' ([^"\\] | "\\" escape)* '"'
    /// ```
    pub fn scan_token<'b>(
        &mut self,
        buffer: &'b mut Vec<u8>,
    ) -> Result<Option<&'b [u8]>, ScanError> {
        // Allow the buffer to have previous content.
        let start = buffer.len();

        // Whether the token exists (even if it has no content).
        let mut exists = false;

        // Loop through non-special chunks and special sequences.
        loop {
            let (chunk, first) = self.scan_unquoted_chunk(|_| false);

            // Copy the non-special chunk into the buffer.
            buffer.extend_from_slice(chunk);
            exists |= !chunk.is_empty();

            // Determine the nature of the special sequence.
            match first {
                Some(b' ' | b'\t' | b'\r' | b'\n') | None => {
                    // This is the end of the token.
                    return Ok(exists.then_some(&buffer[start..]));
                }

                Some(b'"') => {
                    // A quoted string within the token.
                    exists = true;
                    self.consume(1);
                    self.scan_quoted(buffer)?;
                }

                Some(b'\\') => {
                    // An escape sequence.
                    exists = true;
                    self.consume(1);
                    buffer.push(self.scan_escape()?);
                }

                Some(_) => {
                    // This is some non-ASCII char or control code.
                    return Err(ScanError::InvalidCharacter);
                }
            }
        }
    }

    /// Parse a chunk of non-special content within a single unquoted token.
    ///
    /// All non-special characters in the input, up to a special character or
    /// the end of the entry, are returned.
    ///
    /// By default, a non-special character is any printable ASCII character
    /// except backslash, left/right parenthesis, double quote, and semicolon.
    /// The caller can specify additional special characters via a predicate.
    /// Note that unquoted left/right parentheses and semicolons should have
    /// been stripped out before calling [`Scanner::new()`].
    ///
    /// The chunk will be returned as a reference to the original input.  No
    /// additional characters will be consumed from the input.  If the scanner
    /// did not reach the end of the input, the delimiting special character
    /// is returned.
    pub fn scan_unquoted_chunk(
        &mut self,
        special: impl Fn(&u8) -> bool,
    ) -> (&'a [u8], Option<u8>) {
        let pos = self
            .remaining
            .iter()
            .position(|b| {
                !b.is_ascii_graphic()
                    || b"();\\\"".contains(b)
                    || (special)(b)
            })
            .unwrap_or(self.remaining.len());

        let (unescaped, rest) = self.remaining.split_at(pos);
        self.remaining = rest;
        (unescaped, self.remaining.first().copied())
    }

    /// Scan a quoted string.
    ///
    /// The scanner should be located immediately after the opening double
    /// quote.  The rest of the quoted string (including the closing double
    /// quote) will be consumed, unescaped, and appended to the given buffer.
    pub fn scan_quoted<'b>(
        &mut self,
        buffer: &'b mut Vec<u8>,
    ) -> Result<&'b [u8], ScanError> {
        // Allow the buffer to have previous content.
        let start = buffer.len();

        // Loop through non-special chunks and special sequences.
        loop {
            // Scan for special sequences.
            let pos = self
                .remaining
                .iter()
                .position(|b| b"\\\"".contains(b))
                .ok_or(ScanError::UnterminatedQuote)?;

            // Copy the non-special chunk to the output.
            buffer.extend_from_slice(&self.remaining[..pos]);

            match self.remaining[pos] {
                b'\\' => {
                    // Parse an escape sequence.
                    self.consume(pos + 1);
                    buffer.push(self.scan_escape()?);
                }

                b'"' => {
                    // The quoted string is complete.  Stop.
                    self.consume(pos + 1);
                    return Ok(&buffer[start..]);
                }

                _ => unreachable!(),
            }
        }
    }

    /// Parse an escape.
    ///
    /// The scanner should be located immediately after the backslash
    /// character.  It parses the regular expression `[0-9]{3}|[^0-9]`.  In
    /// the first case, the three decimal digits are interpreted as the value
    /// of the byte (which must be at most 255).  In the second case, the byte
    /// is copied over verbatim.  The escape is consumed and the unescaped
    /// byte value is returned.
    pub fn scan_escape(&mut self) -> Result<u8, ScanError> {
        let (&first, rest) = self
            .remaining
            .split_first()
            .ok_or(ScanError::IncompleteEscape)?;

        if first.is_ascii_digit() {
            // This is a decimal escape.

            if self.remaining.len() < 3 {
                return Err(ScanError::IncompleteEscape);
            }

            let (num, rest) = self.remaining.split_at(3);
            self.remaining = rest;
            core::str::from_utf8(num)
                .ok()
                .and_then(|num| num.parse().ok())
                .ok_or(ScanError::InvalidDecimalEscape)
        } else {
            // This is a regular escape.
            self.remaining = rest;
            Ok(first)
        }
    }

    /// Skip whitespace.
    ///
    /// Any whitespace at the beginning of the scanner, including newlines,
    /// will be skipped over.  The scanner will then start at a non-whitespace
    /// token (or will have run out of input).  `true` is returned if at least
    /// one whitespace character was consumed.
    pub fn skip_ws(&mut self) -> bool {
        let amount = self
            .remaining
            .iter()
            .take_while(|&b| b.is_ascii_whitespace())
            .count();
        self.remaining = &self.remaining[amount..];
        amount != 0
    }

    /// Consume the specified number of bytes.
    ///
    /// The caller can inspect the remaining bytes with [`Self::remaining()`],
    /// parse them manually, and then mark them as consumed with this method.
    ///
    /// # Panics
    ///
    /// Panics if the number of bytes exceeds [`Self::remaining()`].
    pub fn consume(&mut self, amount: usize) {
        assert!(amount <= self.remaining.len());
        self.remaining = &self.remaining[amount..];
    }
}

//----------- Scan -----------------------------------------------------------

/// A type that can be scanned from a zonefile entry.
pub trait Scan<'a>: Sized {
    /// Scan a value from a zonefile entry.
    ///
    /// Data to be stored indirectly can be allocated on the given [`Bump`].
    /// Temporary allocations (e.g. when building byte strings) can be built
    /// on the provided [`Vec`] (which may have existing content that should
    /// not be removed).
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a Bump,
        buffer: &mut Vec<u8>,
    ) -> Result<Self, ScanError>;
}

macro_rules! impl_scan_int {
    ($type:ty) => {
        impl Scan<'_> for $type {
            fn scan(
                scanner: &mut Scanner<'_>,
                _alloc: &'_ Bump,
                _buffer: &mut Vec<u8>,
            ) -> Result<Self, ScanError> {
                scanner.scan_plain_token()?.parse::<$type>().map_err(|err| {
                    ScanError::Custom(match err.kind() {
                        IntErrorKind::PosOverflow => {
                            "Integer value too large for field"
                        }
                        IntErrorKind::InvalidDigit => {
                            "Invalid decimal integer"
                        }
                        IntErrorKind::NegOverflow => {
                            "A non-negative integer was expected"
                        }
                        // We have already checked for other kinds of errors.
                        _ => unreachable!(),
                    })
                })
            }
        }
    };
}

impl_scan_int!(u8);
impl_scan_int!(u16);
impl_scan_int!(u32);
impl_scan_int!(u64);
impl_scan_int!(usize);

impl_scan_int!(i8);
impl_scan_int!(i16);
impl_scan_int!(i32);
impl_scan_int!(i64);
impl_scan_int!(isize);

//----------- ScanError ------------------------------------------------------

/// An error in scanning a zonefile entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanError {
    /// A quoted string was not terminated.
    UnterminatedQuote,

    /// This token is not allowed to contain a quoted string.
    ProhibitedQuote,

    /// This token is not allowed to contain escapes.
    ProhibitedEscape,

    /// An incomplete escape sequence was found.
    IncompleteEscape,

    /// An invalid decimal escape was found.
    InvalidDecimalEscape,

    /// An unescaped non-ASCII character or ASCII control code was found.
    InvalidCharacter,

    /// The input was incomplete.
    Incomplete,

    /// A custom record scanning error occurred.
    Custom(&'static str),
}

#[cfg(feature = "std")]
impl std::error::Error for ScanError {}

//--- Formatting

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnterminatedQuote => "a quoted string was not terminated",
            Self::ProhibitedQuote => "a token incorrectly uses quotes",
            Self::ProhibitedEscape => "a token incorrectly uses escapes",
            Self::IncompleteEscape => "the entry ended on a partial escape",
            Self::InvalidDecimalEscape => {
                "an invalid decimal escape was found"
            }
            Self::InvalidCharacter => "an unprintable character was found",
            Self::Incomplete => "the input was incomplete",
            Self::Custom(s) => s,
        })
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::Scanner;

    #[test]
    fn rfc1035() {
        let cases: [(&str, &[Option<&str>]); 18] = [
            (
                "\
@   IN  SOA     VENERA      Action\\.domains 
                                 20     
                                 7200   
                                 600    
                                 3600000
                                 60    ",
                &[
                    Some("@"),
                    Some("IN"),
                    Some("SOA"),
                    Some("VENERA"),
                    Some("Action.domains"),
                    Some("20"),
                    Some("7200"),
                    Some("600"),
                    Some("3600000"),
                    Some("60"),
                ],
            ),
            (
                "        NS      A.ISI.EDU.",
                &[None, Some("NS"), Some("A.ISI.EDU.")],
            ),
            (
                "        NS      VENERA",
                &[None, Some("NS"), Some("VENERA")],
            ),
            ("        NS      VAXA", &[None, Some("NS"), Some("VAXA")]),
            (
                "        MX      10      VENERA",
                &[None, Some("MX"), Some("10"), Some("VENERA")],
            ),
            (
                "        MX      20      VAXA",
                &[None, Some("MX"), Some("20"), Some("VAXA")],
            ),
            (
                "A       A       26.3.0.103",
                &[Some("A"), Some("A"), Some("26.3.0.103")],
            ),
            (
                "VENERA  A       10.1.0.52",
                &[Some("VENERA"), Some("A"), Some("10.1.0.52")],
            ),
            (
                "        A       128.9.0.32",
                &[None, Some("A"), Some("128.9.0.32")],
            ),
            (
                "VAXA    A       10.2.0.27",
                &[Some("VAXA"), Some("A"), Some("10.2.0.27")],
            ),
            (
                "        A       128.9.0.33",
                &[None, Some("A"), Some("128.9.0.33")],
            ),
            (
                "$INCLUDE <SUBSYS>ISI-MAILBOXES.TXT",
                &[Some("$INCLUDE"), Some("<SUBSYS>ISI-MAILBOXES.TXT")],
            ),
            (
                "MOE     MB      A.ISI.EDU.",
                &[Some("MOE"), Some("MB"), Some("A.ISI.EDU.")],
            ),
            (
                "LARRY   MB      A.ISI.EDU.",
                &[Some("LARRY"), Some("MB"), Some("A.ISI.EDU.")],
            ),
            (
                "CURLEY  MB      A.ISI.EDU.",
                &[Some("CURLEY"), Some("MB"), Some("A.ISI.EDU.")],
            ),
            (
                "STOOGES MG      MOE",
                &[Some("STOOGES"), Some("MG"), Some("MOE")],
            ),
            ("        MG      LARRY", &[None, Some("MG"), Some("LARRY")]),
            (
                "        MG      CURLEY",
                &[None, Some("MG"), Some("CURLEY")],
            ),
        ];

        let mut buffer = Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input.as_bytes(), None);
            for &expected in expected {
                let token = scanner.scan_token(&mut buffer).unwrap();
                assert_eq!(token, expected.map(|s| s.as_bytes()));
                scanner.skip_ws();
            }
            assert_eq!(scanner.scan_token(&mut buffer), Ok(None));
        }
    }
}
