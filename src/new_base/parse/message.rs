//! Parsing DNS messages.

use core::iter::FusedIterator;

use crate::{
    new_base::{name::RevNameBuf, Header, Message, MessageItem},
    new_rdata::{Opt, RecordData},
};

use super::{ParseBytesZC, ParseError, SplitMessageBytes};

//----------- MessageParser --------------------------------------------------

/// A DNS message parser.
///
/// This offers a mid-level API for parsing the contents of a [`Message`].
#[derive(Clone)]
pub struct MessageParser<'a> {
    /// The message being parsed.
    message: &'a Message,

    /// The current offset into the message contents.
    offset: usize,

    /// The current section number.
    section: u8,

    /// The number of remaining items in this section.
    remaining_items: u16,
}

/// A parsed message item.
///
/// This is the concrete type of items parsed by [`MessageParser`].
pub type ParsedMessageItem<'a> =
    MessageItem<RevNameBuf, RecordData<'a, RevNameBuf>, &'a Opt>;

//--- Construction

impl<'a> MessageParser<'a> {
    /// Create a new [`MessageParser`].
    ///
    /// # Errors
    ///
    /// Fails if the byte sequence is less than 12 bytes long (as this can
    /// never constitute a valid DNS message).
    pub fn new(bytes: &'a [u8]) -> Result<Self, ParseError> {
        Message::parse_bytes_by_ref(bytes).map(Self::for_message)
    }

    /// Prepare a parser for the given message.
    pub const fn for_message(message: &'a Message) -> Self {
        Self {
            message,
            offset: 0,
            section: 0,
            remaining_items: message.header.counts.questions.get(),
        }
    }
}

//--- Inspection

impl<'a> MessageParser<'a> {
    /// The overall message being parsed.
    pub const fn message(&self) -> &'a Message {
        self.message
    }

    /// The message header.
    pub const fn header(&self) -> &'a Header {
        &self.message.header
    }

    /// The current offset into the message contents.
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

//--- Iteration

impl<'a> Iterator for MessageParser<'a> {
    type Item = Result<ParsedMessageItem<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Check for a remaining item.
        while self.remaining_items == 0 {
            if self.section < 3 {
                self.section += 1;
                let counts = self.message.header.counts;
                let count = counts.as_array()[self.section as usize];
                self.remaining_items = count.get();
            } else {
                // We're out of items.
                return None;
            }
        }

        /// Parse a specific variont of [`MessageItem`].
        fn parse_variant<'a, T: SplitMessageBytes<'a>>(
            parser: &mut MessageParser<'a>,
            f: impl FnOnce(T) -> ParsedMessageItem<'a>,
        ) -> Result<ParsedMessageItem<'a>, ParseError> {
            T::split_message_bytes(&parser.message.contents, parser.offset)
                .map(|(data, offset)| {
                    parser.offset = offset;
                    (f)(data)
                })
        }

        // Parse the item.
        self.remaining_items -= 1;
        let remaining = &self.message.contents[self.offset..];
        let item = match self.section {
            0 => parse_variant(self, MessageItem::Question),
            1 => parse_variant(self, MessageItem::Answer),
            2 => parse_variant(self, MessageItem::Authority),

            // An EDNS record starts with '0 0 41': the root record name and
            // the OPT record type.
            3 if remaining.starts_with(&[0, 0, 41]) => {
                parse_variant(self, MessageItem::Edns)
            }

            3 => parse_variant(self, MessageItem::Additional),
            _ => unreachable!(),
        };

        // If parsing failed, fuse the iterator.
        if item.is_err() {
            self.section = 3;
            self.remaining_items = 0;
        }

        Some(item)
    }
}

impl FusedIterator for MessageParser<'_> {}
