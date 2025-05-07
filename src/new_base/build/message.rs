//! Building whole DNS messages.

use core::fmt;

use crate::{
    new_base::{
        wire::{ParseBytesZC, U16},
        Header, HeaderFlags, Message, MessageItem, Question, Record,
        SectionCounts,
    },
    new_edns::EdnsRecord,
};

use super::{BuildBytes, BuildInMessage, NameCompressor, TruncationError};

//----------- MessageBuilder -------------------------------------------------

/// A builder for a whole DNS message.
pub struct MessageBuilder<'b, 'c> {
    /// The message being built.
    message: &'b mut Message,

    /// The offset data is being written to.
    offset: usize,

    /// The name compressor.
    compressor: &'c mut NameCompressor,
}

//--- Initialization

impl<'b, 'c> MessageBuilder<'b, 'c> {
    /// Begin building a DNS message.
    ///
    /// The buffer will be initialized with the given message ID and flags.
    /// The name compressor will be reset in case it was used before.
    ///
    /// # Panics
    ///
    /// Panics if the buffer is less than 12 bytes long (which is the minimum
    /// possible size for a DNS message).
    #[must_use]
    pub fn new(
        buffer: &'b mut [u8],
        id: U16,
        flags: HeaderFlags,
        compressor: &'c mut NameCompressor,
    ) -> Self {
        let message = Message::parse_bytes_in(buffer)
            .expect("The caller's buffer is at least 12 bytes big");
        message.header = Header {
            id,
            flags,
            counts: SectionCounts::default(),
        };
        // TODO: Reset the name compressor.
        Self {
            message,
            offset: 0,
            compressor,
        }
    }
}

//--- Inspection

impl MessageBuilder<'_, '_> {
    /// The message header.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.message.header
    }

    /// The message header, mutably.
    #[must_use]
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.message.header
    }

    /// The message built thus far.
    #[must_use]
    pub fn message(&self) -> &Message {
        self.message.truncate(self.offset)
    }

    /// The message built thus far, mutably.
    ///
    /// Compressed names in the message must not be modified here, as the name
    /// compressor relies on them.  Modifying them will break name compression
    /// and result in misformatted messages.
    #[must_use]
    pub fn message_mut(&mut self) -> &mut Message {
        self.message.truncate_mut(self.offset)
    }

    /// The name compressor.
    #[must_use]
    pub fn compressor(&self) -> &NameCompressor {
        self.compressor
    }
}

//--- Interaction

impl<'b> MessageBuilder<'b, '_> {
    /// End the builder, returning the built message.
    #[must_use]
    pub fn finish(self) -> &'b mut Message {
        self.message.truncate_mut(self.offset)
    }

    /// Reborrow the builder with a shorter lifetime.
    #[must_use]
    pub fn reborrow(&mut self) -> MessageBuilder<'_, '_> {
        MessageBuilder {
            message: self.message,
            offset: self.offset,
            compressor: self.compressor,
        }
    }

    /// Limit the total message size.
    ///
    /// The message will not be allowed to exceed the given size, in bytes.
    /// Only the message header and contents are counted; the enclosing UDP
    /// or TCP packet size is not considered.  If the message already exceeds
    /// this size, a [`TruncationError`] is returned.
    pub fn limit_to(&mut self, size: usize) -> Result<(), TruncationError> {
        if 12 + self.offset <= size {
            // Move out of 'message' so that the full lifetime is available.
            // See the 'replace_with' and 'take_mut' crates.
            let size = (size - 12).min(self.message.contents.len());
            let message = unsafe { core::ptr::read(&self.message) };
            // NOTE: Precondition checked, will not panic.
            let message = message.truncate_mut(size);
            unsafe { core::ptr::write(&mut self.message, message) };
            Ok(())
        } else {
            Err(TruncationError)
        }
    }

    /// Truncate the message.
    ///
    /// This will remove all message contents and mark it as truncated.
    pub fn truncate(&mut self) {
        self.message.header.flags.set_tc(true);
        self.offset = 0;
        // TODO: Reset the name compressor.
    }

    /// Append a message item.
    ///
    /// ## Errors
    ///
    /// If the item cannot be appended (because it needs to come before items
    /// already in the message), [`Misplaced`] is returned.  If the item does
    /// not fit in the message buffer, [`Truncated`] is returned.
    ///
    /// [`Misplaced`]: MessageBuildError::Misplaced
    /// [`Truncated`]: MessageBuildError::Truncated
    pub fn push<N, RD, ED>(
        &mut self,
        item: &MessageItem<N, RD, ED>,
    ) -> Result<(), MessageBuildError>
    where
        N: BuildInMessage,
        RD: BuildInMessage,
        ED: BuildBytes,
    {
        // Determine the section number.
        let section = match item {
            MessageItem::Question(_) => 0,
            MessageItem::Answer(_) => 1,
            MessageItem::Authority(_) => 2,
            MessageItem::Additional(_) => 3,
            MessageItem::Edns(_) => 3,
        };

        // Make sure this item is not misplaced.
        let counts = self.message.header.counts.as_array_mut();
        if counts[section + 1..].iter().any(|c| c.get() != 0) {
            return Err(MessageBuildError::Misplaced);
        }

        // Try to build the item.
        self.offset = item.build_in_message(
            &mut self.message.contents,
            self.offset,
            self.compressor,
        )?;

        // TODO: Reset the name compressor in case of failure.

        // Update the section counts, now that we have succeeded.
        counts[section] += 1;

        Ok(())
    }

    /// Append a question.
    ///
    /// ## Errors
    ///
    /// If the item cannot be appended (because it needs to come before items
    /// already in the message), [`Misplaced`] is returned.  If the item does
    /// not fit in the message buffer, [`Truncated`] is returned.
    ///
    /// [`Misplaced`]: MessageBuildError::Misplaced
    /// [`Truncated`]: MessageBuildError::Truncated
    pub fn push_question<N: BuildInMessage>(
        &mut self,
        question: &Question<N>,
    ) -> Result<(), MessageBuildError> {
        let question = question.transform_ref(|n| n);
        self.push(&MessageItem::<&N, (), ()>::Question(question))
    }

    /// Append an answer record.
    ///
    /// ## Errors
    ///
    /// If the item cannot be appended (because it needs to come before items
    /// already in the message), [`Misplaced`] is returned.  If the item does
    /// not fit in the message buffer, [`Truncated`] is returned.
    ///
    /// [`Misplaced`]: MessageBuildError::Misplaced
    /// [`Truncated`]: MessageBuildError::Truncated
    pub fn push_answer<N: BuildInMessage, D: BuildInMessage>(
        &mut self,
        answer: &Record<N, D>,
    ) -> Result<(), MessageBuildError> {
        let answer = answer.transform_ref(|n| n, |d| d);
        self.push(&MessageItem::<&N, &D, ()>::Answer(answer))
    }

    /// Append an authority record.
    ///
    /// ## Errors
    ///
    /// If the item cannot be appended (because it needs to come before items
    /// already in the message), [`Misplaced`] is returned.  If the item does
    /// not fit in the message buffer, [`Truncated`] is returned.
    ///
    /// [`Misplaced`]: MessageBuildError::Misplaced
    /// [`Truncated`]: MessageBuildError::Truncated
    pub fn push_authority<N: BuildInMessage, D: BuildInMessage>(
        &mut self,
        authority: &Record<N, D>,
    ) -> Result<(), MessageBuildError> {
        let authority = authority.transform_ref(|n| n, |d| d);
        self.push(&MessageItem::<&N, &D, ()>::Authority(authority))
    }

    /// Append an additional record.
    ///
    /// ## Errors
    ///
    /// If the item does not fit in the message buffer, [`TruncationError`] is
    /// returned.
    pub fn push_additional<N: BuildInMessage, D: BuildInMessage>(
        &mut self,
        additional: &Record<N, D>,
    ) -> Result<(), TruncationError> {
        let additional = additional.transform_ref(|n| n, |d| d);
        self.push(&MessageItem::<&N, &D, ()>::Additional(additional))
            .map_err(|err| match err {
                MessageBuildError::Misplaced => {
                    unreachable!("An additional record is never misplaced")
                }
                MessageBuildError::Truncated(err) => err,
            })
    }

    /// Append an EDNS record.
    ///
    /// ## Errors
    ///
    /// If the item does not fit in the message buffer, [`TruncationError`] is
    /// returned.
    pub fn push_edns<D: ?Sized + BuildBytes>(
        &mut self,
        edns: &EdnsRecord<D>,
    ) -> Result<(), TruncationError> {
        let edns = edns.transform_ref(|d| d);
        self.push(&MessageItem::<(), (), &D>::Edns(edns))
            .map_err(|err| match err {
                MessageBuildError::Misplaced => {
                    unreachable!("An additional record is never misplaced")
                }
                MessageBuildError::Truncated(err) => err,
            })
    }
}

//----------- MessageBuildError ----------------------------------------------

/// A component of a DNS message could not be built.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MessageBuildError {
    /// A message item was placed in the wrong section.
    ///
    /// DNS message items (questions, answers, additionals, etc.) must come in
    /// a fixed order; this error is returned if an item could not be added in
    /// the right order (i.e. items from later sections would come before it).
    Misplaced,

    /// A message item was too large to fit.
    Truncated(TruncationError),
}

#[cfg(feature = "std")]
impl std::error::Error for MessageBuildError {}

impl From<TruncationError> for MessageBuildError {
    fn from(value: TruncationError) -> Self {
        Self::Truncated(value)
    }
}

//--- Formatting

impl fmt::Display for MessageBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Misplaced => {
                "a DNS message item was placed in the wrong order"
            }
            Self::Truncated(_) => "a DNS message item was too large to fit",
        })
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use crate::new_base::name::RevNameBuf;
    use crate::new_base::wire::U16;
    use crate::new_base::{
        HeaderFlags, QClass, QType, Question, RClass, RType, Record, TTL,
    };
    use crate::new_rdata::{RecordData, A};

    use super::{MessageBuilder, NameCompressor};

    #[test]
    fn new() {
        let mut buffer = [0u8; 12];
        let mut compressor = NameCompressor::default();

        let mut builder = MessageBuilder::new(
            &mut buffer,
            U16::new(0),
            HeaderFlags::default(),
            &mut compressor,
        );

        assert_eq!(&builder.message().contents, &[] as &[u8]);
        assert_eq!(&builder.message_mut().contents, &[] as &[u8]);
    }

    #[test]
    fn build_question() {
        let mut buffer = [0u8; 33];
        let mut compressor = NameCompressor::default();
        let mut builder = MessageBuilder::new(
            &mut buffer,
            U16::new(0),
            HeaderFlags::default(),
            &mut compressor,
        );

        let question = Question::<RevNameBuf> {
            qname: "www.example.org".parse().unwrap(),
            qtype: QType::A,
            qclass: QClass::IN,
        };
        builder.push_question(&question).unwrap();

        let contents = b"\x03www\x07example\x03org\x00\x00\x01\x00\x01";
        assert_eq!(&builder.message().contents, contents);
    }

    #[test]
    fn build_record() {
        let mut buffer = [0u8; 43];
        let mut compressor = NameCompressor::default();
        let mut builder = MessageBuilder::new(
            &mut buffer,
            U16::new(0),
            HeaderFlags::default(),
            &mut compressor,
        );

        let record = Record::<RevNameBuf, _> {
            rname: "www.example.org".parse().unwrap(),
            rtype: RType::A,
            rclass: RClass::IN,
            ttl: TTL::from(42),
            rdata: RecordData::<()>::A(A {
                octets: [127, 0, 0, 1],
            }),
        };
        builder.push_answer(&record).unwrap();

        assert_eq!(builder.message().header.counts.answers.get(), 1);
        let contents = b"\x03www\x07example\x03org\x00\x00\x01\x00\x01\x00\x00\x00\x2A\x00\x04\x7F\x00\x00\x01";
        assert_eq!(&builder.message().contents, contents.as_slice());
    }
}
