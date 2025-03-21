//! Parsing DNS messages from the wire format.
//!
//! This module provides [`ParseMessageBytes`] and [`SplitMessageBytes`],
//! which are specializations of [`ParseBytes`] and [`SplitBytes`] to DNS
//! messages.  When parsing data within a DNS message, these traits allow
//! access to all preceding bytes in the message so that compressed names can
//! be resolved.
//!
//! [`ParseBytes`]: super::wire::ParseBytes
//! [`SplitBytes`]: super::wire::SplitBytes

pub use super::wire::ParseError;

use super::wire::{ParseBytesByRef, SplitBytesByRef};

//----------- Message parsing traits -----------------------------------------

/// A type that can be parsed from a DNS message.
pub trait SplitMessageBytes<'a>: Sized + ParseMessageBytes<'a> {
    /// Parse a value from the start of a byte string within a DNS message.
    ///
    /// The contents of the DNS message is provided as `contents`.
    /// `contents[start..]` is the beginning of the input to be parsed.  The
    /// earlier bytes are provided for resolving compressed domain names.
    ///
    /// If parsing is successful, the parsed value and the offset for the rest
    /// of the input are returned.  If `len` bytes were parsed to form `self`,
    /// `start + len` should be the returned offset.
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError>;
}

/// A type that can be parsed from bytes in a DNS message.
pub trait ParseMessageBytes<'a>: Sized {
    /// Parse a value from bytes in a DNS message.
    ///
    /// The contents of the DNS message (up to and including the actual bytes
    /// to be parsed) is provided as `contents`.  `contents[start..]` is the
    /// input to be parsed.  The earlier bytes are provided for resolving
    /// compressed domain names.
    ///
    /// If parsing is successful, the parsed value is returned.
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError>;
}

impl<'a, T: ?Sized + SplitBytesByRef> SplitMessageBytes<'a> for &'a T {
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        T::split_bytes_by_ref(&contents[start..])
            .map(|(this, rest)| (this, contents.len() - rest.len()))
    }
}

impl<'a, T: ?Sized + ParseBytesByRef> ParseMessageBytes<'a> for &'a T {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        T::parse_bytes_by_ref(&contents[start..])
    }
}
