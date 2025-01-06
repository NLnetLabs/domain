//! Parsing DNS messages from the wire format.

use core::ops::Range;

mod message;
pub use message::{MessagePart, ParseMessage, VisitMessagePart};

mod question;
pub use question::{ParseQuestion, ParseQuestions, VisitQuestion};

mod record;
pub use record::{ParseRecord, ParseRecords, VisitRecord};

pub use super::wire::ParseError;

use super::{
    wire::{AsBytes, ParseBytesByRef, SplitBytesByRef},
    Message,
};

//----------- Message-aware parsing traits -----------------------------------

/// A type that can be parsed from a DNS message.
pub trait SplitFromMessage<'a>: Sized + ParseFromMessage<'a> {
    /// Parse a value of [`Self`] from the start of a byte string within a
    /// particular DNS message.
    ///
    /// If parsing is successful, the parsed value and the rest of the string
    /// are returned.  Otherwise, a [`ParseError`] is returned.
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError>;
}

/// A type that can be parsed from a string in a DNS message.
pub trait ParseFromMessage<'a>: Sized {
    /// Parse a value of [`Self`] from a byte string within a particular DNS
    /// message.
    ///
    /// If parsing is successful, the parsed value is returned.  Otherwise, a
    /// [`ParseError`] is returned.
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError>;
}

impl<'a, T: ?Sized + SplitBytesByRef> SplitFromMessage<'a> for &'a T {
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let message = message.as_bytes();
        let bytes = message.get(start..).ok_or(ParseError)?;
        let (this, rest) = T::split_bytes_by_ref(bytes)?;
        Ok((this, message.len() - rest.len()))
    }
}

impl<'a, T: ?Sized + ParseBytesByRef> ParseFromMessage<'a> for &'a T {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        let message = message.as_bytes();
        let bytes = message.get(range).ok_or(ParseError)?;
        T::parse_bytes_by_ref(bytes)
    }
}
