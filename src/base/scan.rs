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

use core::ops::Range;
use core::{fmt, str};

#[cfg(feature = "std")]
use std::borrow::Cow;

use super::Ttl;

//------------ Scan ---------------------------------------------------------

/// Scan items from the presentation format.
///
/// This trait is implemented by types representing semantic components of a
/// DNS record in the presentation format.
pub trait Scan: Sized {
    /// Scan a value from tokens.
    ///
    /// Given an iterator over tokens, this function extracts a value of this
    /// type, returning a [`ScanError`] on failure.
    ///
    /// Note that the token iterator does not allow for lookahead; after taking
    /// the first token, it is up to this function to decide when to take more
    /// tokens.  It cannot peek ahead to decide whether to take them.
    fn scan(tokens: &mut Tokenizer<'_>) -> Result<Self, ScanError>;
}

macro_rules! impl_scan_unsigned {
    ($type:ident) => {
        impl Scan for $type {
            fn scan(tokens: &mut Tokenizer<'_>) -> Result<Self, ScanError> {
                use core::num::IntErrorKind;

                // Only a single token is required; retrieve it.
                let text = tokens.next().ok_or(ScanError::Empty)?.as_ref();

                text.parse::<$type>().map_err(|e| {
                    ScanError::custom(match e.kind() {
                        IntErrorKind::InvalidDigit => {
                            "expected decimal number"
                        }
                        IntErrorKind::PosOverflow => {
                            "decimal number overflow"
                        }
                        _ => unreachable!(),
                    })
                })
            }
        }
    };
}

impl_scan_unsigned!(u8);
impl_scan_unsigned!(u16);
impl_scan_unsigned!(u32);
impl_scan_unsigned!(u64);
impl_scan_unsigned!(u128);

impl Scan for Ttl {
    fn scan(tokens: &mut Tokenizer<'_>) -> Result<Self, ScanError> {
        u32::scan(tokens).map(Ttl::from_secs)
    }
}

//------------ Tokenizer -----------------------------------------------------

/// A presentation format tokenizer.
///
/// Text in the presentation format consists of whitespace-separated tokens.
/// Tokens can contain whitespace if they are quoted strings.  This type will
/// parse the text, correctly split it into tokens, and allow iterating over
/// them.  This greatly simplifies the task of parsing into semantic elements.
pub struct Tokenizer<'a> {
    /// The underlying input string.
    ///
    /// This is the entire string -- `pos` provides the current position of
    /// the tokenizer within it.
    input: &'a str,

    /// The current position.
    ///
    /// This is the index of the first unexamined byte in `input`.  If it
    /// falls outside the range of `input`, then tokenization is complete.
    pos: usize,
}

impl<'a> Tokenizer<'a> {
    /// Prepare to tokenize a string.
    #[must_use]
    pub fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    /// Extract the next token from the text.
    pub fn next(&mut self) -> Result<Token<'a>, ScanError> {
        // TODO: We could use 'memchr' to track the position of the next
        // double-quote, backslash, or semicolon.  These positions would be
        // stored in the tokenizer state and updated when required.  We don't
        // expect them to occur very often -- otherwise a simple for loop
        // would be fast enough.

        // Since we're looking for ASCII characters, it's easier to work with
        // the byte-wise version of the input.  The indices are identical.
        let input = self.input.as_bytes();

        // If there isn't any more input left, just stop.
        if self.pos >= input.len() {
            return Err(ScanError::missing());
        }

        // We should be at the beginning of the next token.  This assumption
        // does not hold at the start of tokenization, so let's fix that.
        if self.pos == 0 {
            self.pos += input
                .iter()
                .position(|b| !b" \t\r\n".contains(b))
                .unwrap_or(self.input.len());

            // We need to repeat this test from the top of the function.
            if self.pos >= input.len() {
                return Err(ScanError::missing());
            }
        }

        // While we should be at the beginning of a token, we might encounter
        // a comment or a newline.  If we had output a token on the same line,
        // we should output a newline token, as this indicates the separation
        // between entries in zone files.
        //
        // So, we loop and skip past all comments and newlines.  If any such
        // skips happened, then we're on a different line than the previous
        // token, so we stop and output a newline token.
        if b";\n".contains(&input[self.pos]) {
            // The token we will output references the newline, so we need to
            // skip ahead to it if we had hit a comment.
            if input[self.pos] == b';' {
                self.pos += input[self.pos..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .unwrap_or(input.len() - self.pos);

                // If we can't find a newline, we can stop already.
                if self.pos >= input.len() {
                    return Err(ScanError::missing());
                }
            }

            // Save the newline position and skip it.
            let newline_pos = self.pos;
            self.pos += 1;

            while self.pos < input.len() {
                // If we reach an actual token, stop.
                if !b";\n".contains(&input[self.pos]) {
                    break;
                }

                if input[self.pos] == b';' {
                    // Skip ahead to and past the newline.
                    self.pos += input[self.pos..]
                        .iter()
                        .position(|&b| b == b'\n')
                        .map_or(input.len() - self.pos, |p| p + 1);
                } else {
                    // Skip past the newline.
                    self.pos += 1;
                }

                // We're now on the next line; skip any whitespace on it.
                self.pos += input[self.pos..]
                    .iter()
                    .position(|b| b" \t\r".contains(b))
                    .unwrap_or(input.len() - self.pos);
            }

            // Output a newline token, so that the token on this line is
            // separated from previous tokens.
            return (self.pos == input.len()).then_some(Token {
                input: self.input,
                pos: newline_pos,
                len: 1,
            });
        }

        // Every token is either a quoted or unquoted string.
        let pos = self.pos;
        let len = if input[self.pos] == b'"' {
            use core::mem::replace;

            // We search for an un-escaped double-quote.
            input[self.pos + 1..]
                .iter()
                .scan(false, |e, &b| Some((replace(e, !*e && b == b'\\'), b)))
                .position(|x| x == (false, b'"'))
                .map_or(input.len() - self.pos, |p| p + 1)
        } else {
            // We search for any whitespace.
            input[self.pos + 1..]
                .iter()
                .position(|b| !b" \t\r".contains(b))
                .unwrap_or(input.len() - self.pos)
        };

        // Move past this token.
        self.pos += len;

        // Ensure the token doesn't contain any invalid characters.
        if input[pos..][..len].any(|&b| b < 0x20 && b != b'\t') {
            return Err(ScanError::custom(
                "ASCII control codes must be escaped",
            ));
        }

        Ok(Token {
            input: self.input,
            pos,
            len,
        })
    }
}

//------------ Token ---------------------------------------------------------

/// A token of text in the presentation format.
#[derive(Copy, Clone, Debug)]
pub struct Token<'a> {
    /// The referenced input text.
    input: &'a str,

    /// The position of this token.
    pos: usize,

    /// The length of this token.
    len: usize,
}

impl<'a> Token<'a> {
    /// The raw content of this token.
    ///
    /// This includes unprocessed escape sequences.
    #[must_use]
    pub fn raw(&self) -> &'a str {
        &self.input[self.pos..][..self.len]
    }

    /// The position of this token in the input.
    #[must_use]
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// The length of this token, in bytes.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// The content of this token, if it contains no escape sequences.
    #[must_use]
    pub fn content(&self) -> Option<&'a str> {
        self.raw().bytes().all(|b| b != b'\\')
    }

    /// Slice into this token.
    ///
    /// This method can be used to break down a token into fragments, so that
    /// each can be processed individually.
    #[must_use]
    pub fn slice(&self, range: Range<usize>) -> Self {
        // TODO: Does this correctly bounds-check the access?
        let _ = self.raw()[range.clone()];

        Self {
            input: self.input,
            pos: self.pos + range.start,
            len: range.len(),
        }
    }

    /// Whether this is a quoted string.
    #[must_use]
    pub fn is_quoted(&self) -> bool {
        self.input.as_bytes()[self.pos] == b'"'
    }

    /// Process a token and write its contents.
    ///
    /// This method reads the contents of the token and processes escape
    /// sequences within it.  Each byte, either from the original text or from
    /// an escape sequence, is passed to the given closure in order.
    pub fn process(&self, mut f: impl FnMut(u8)) -> Result<(), ScanError> {
        let input = self.raw().as_bytes();
        let mut pos = 0;
        while pos < input.len() {
            if input[pos] == b'\\' {
                if pos + 1 >= input.len() {
                    return Err(ScanError::custom(
                        "incomplete escape sequence",
                    ));
                }

                if input[pos + 1].is_ascii_digit() {
                    // Parse '\DDD' with 3 octal digits as a byte.
                    if pos + 3 >= input.len() {
                        return Err(ScanError::custom(
                            "incomplete escape sequence",
                        ));
                    }

                    let seq = &input[pos + 1][..3];
                    let val = u8::from_str_radix(seq, 8).map_err(|_| {
                        ScanError::custom("invalid escape sequence")
                    })?;
                    (f)(val);
                    pos += 4;
                } else {
                    // Parse '\X' with a printable ASCII character.
                    if !input[pos + 1].is_ascii_graphic() {
                        return Err(ScanError::custom(
                            "invalid escape sequence",
                        ));
                    }

                    (f)(input[pos + 1]);
                    pos += 2;
                }
            } else {
                (f)(input[pos]);
                pos += 1;
            }
        }
        Ok(())
    }

    /// The processed content of a token.
    ///
    /// This is the same as [`Self::process()`], but it will return the data as
    /// a plain reference (if there are no escape sequences in the token) or as
    /// an allocated byte string.
    #[cfg(feature = "std")]
    pub fn processed_bytes(&self) -> Result<Cow<'a, [u8]>, ScanError> {
        if let Some(content) = self.content {
            return Ok(Cow::Borrowed(content.as_bytes()));
        }

        let mut buffer = std::vec::Vec::new();
        self.process(|b| buffer.push(b))?;
        Ok(buffer)
    }
}

//============ Error Types ===================================================

//------------ ScanError -----------------------------------------------------

/// An error during scanning.
#[derive(Clone, Debug)]
pub struct ScanError {
    /// The error message.
    msg: &'static str,
}

impl ScanError {
    fn custom(msg: &'static str) -> Self {
        Self { msg }
    }

    fn missing() -> Self {
        Self {
            msg: "unexpected end of text",
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ScanError {}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    //use super::*;

    // TODO: Test 'Tokenizer::next()'.
    // TODO: Test 'Token::process()'.
}
