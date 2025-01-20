//! Parsing DNS messages from the wire format.
//!
//! This module provides [`ParseFromMessage`] and [`SplitFromMessage`], which
//! are specializations of [`ParseBytes`] and [`SplitBytes`] to DNS messages.
//! When parsing data within a DNS message, these traits allow access to all
//! preceding bytes in the message so that compressed names can be resolved.
//!
//! [`ParseBytes`]: super::wire::ParseBytes
//! [`SplitBytes`]: super::wire::SplitBytes

pub use super::wire::ParseError;

use super::{
    wire::{ParseBytesByRef, SplitBytesByRef},
    Message,
};

//----------- Message-aware parsing traits -----------------------------------

/// A type that can be parsed from a DNS message.
pub trait SplitFromMessage<'a>: Sized + ParseFromMessage<'a> {
    /// Parse a value from the start of a byte string within a DNS message.
    ///
    /// The byte string to parse is `message.contents[start..]`.  The previous
    /// data in the message can be used for resolving compressed names.
    ///
    /// If parsing is successful, the parsed value and the offset for the rest
    /// of the input are returned.  If `len` bytes were parsed to form `self`,
    /// `start + len` should be the returned offset.
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError>;
}

/// A type that can be parsed from a string in a DNS message.
pub trait ParseFromMessage<'a>: Sized {
    /// Parse a value from a byte string within a DNS message.
    ///
    /// The byte string to parse is `message.contents[start..]`.  The previous
    /// data in the message can be used for resolving compressed names.
    ///
    /// If parsing is successful, the parsed value is returned.
    fn parse_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<Self, ParseError>;
}

impl<'a, T: ?Sized + SplitBytesByRef> SplitFromMessage<'a> for &'a T {
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let bytes = message.contents.get(start..).ok_or(ParseError)?;
        let (this, rest) = T::split_bytes_by_ref(bytes)?;
        Ok((this, bytes.len() - rest.len()))
    }
}

impl<'a, T: ?Sized + ParseBytesByRef> ParseFromMessage<'a> for &'a T {
    fn parse_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<Self, ParseError> {
        let bytes = message.contents.get(start..).ok_or(ParseError)?;
        T::parse_bytes_by_ref(bytes)
    }
}
