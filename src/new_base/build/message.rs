//! Building whole DNS messages.

use core::cell::UnsafeCell;

use crate::new_base::{
    wire::{ParseBytesByRef, TruncationError},
    Header, Message, Question, RClass, RType, Record, TTL,
};

use super::{
    BuildIntoMessage, Builder, BuilderContext, MessageState, QuestionBuilder,
    RecordBuilder,
};

//----------- MessageBuilder -------------------------------------------------

/// A builder for a whole DNS message.
///
/// This is a high-level building interface, offering methods to put together
/// entire questions and records.  It directly writes into an allocated buffer
/// (on the stack or the heap).
pub struct MessageBuilder<'b> {
    /// The message being constructed.
    message: &'b mut Message,

    /// Context for building.
    pub(super) context: &'b mut BuilderContext,
}

//--- Initialization

impl<'b> MessageBuilder<'b> {
    /// Initialize an empty [`MessageBuilder`].
    ///
    /// The message header is left uninitialized.  use [`Self::header_mut()`]
    /// to initialize it.
    ///
    /// # Panics
    ///
    /// Panics if the buffer is less than 12 bytes long (which is the minimum
    /// possible size for a DNS message).
    pub fn new(
        buffer: &'b mut [u8],
        context: &'b mut BuilderContext,
    ) -> Self {
        let message = Message::parse_bytes_by_mut(buffer)
            .expect("The caller's buffer is at least 12 bytes big");
        *context = BuilderContext::default();
        Self { message, context }
    }
}

//--- Inspection

impl<'b> MessageBuilder<'b> {
    /// The message header.
    pub fn header(&self) -> &Header {
        &self.message.header
    }

    /// The message header, mutably.
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.message.header
    }

    /// The message built thus far.
    pub fn message(&self) -> &Message {
        self.message.slice_to(self.context.size)
    }

    /// The message built thus far, mutably.
    ///
    /// # Safety
    ///
    /// The caller must not modify any compressed names among these bytes.
    /// This can invalidate name compression state.
    pub unsafe fn message_mut(&mut self) -> &mut Message {
        self.message.slice_to_mut(self.context.size)
    }

    /// The builder context.
    pub fn context(&self) -> &BuilderContext {
        self.context
    }
}

//--- Interaction

impl MessageBuilder<'_> {
    /// Reborrow the builder with a shorter lifetime.
    pub fn reborrow(&mut self) -> MessageBuilder<'_> {
        MessageBuilder {
            message: self.message,
            context: self.context,
        }
    }

    /// Limit the total message size.
    ///
    /// The message will not be allowed to exceed the given size, in bytes.
    /// Only the message header and contents are counted; the enclosing UDP
    /// or TCP packet size is not considered.  If the message already exceeds
    /// this size, a [`TruncationError`] is returned.
    ///
    /// # Panics
    ///
    /// Panics if the given size is less than 12 bytes.
    pub fn limit_to(&mut self, size: usize) -> Result<(), TruncationError> {
        if 12 + self.context.size <= size {
            // Move out of 'message' so that the full lifetime is available.
            // See the 'replace_with' and 'take_mut' crates.
            debug_assert!(size < 12 + self.message.contents.len());
            let message = unsafe { core::ptr::read(&self.message) };
            // NOTE: Precondition checked, will not panic.
            let message = message.slice_to_mut(size - 12);
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
        self.message.header.flags =
            self.message.header.flags.set_truncated(true);
        *self.context = BuilderContext::default();
    }

    /// Obtain a [`Builder`].
    pub(super) fn builder(&mut self, start: usize) -> Builder<'_> {
        debug_assert!(start <= self.context.size);
        unsafe {
            let contents = &mut self.message.contents;
            let contents = contents as *mut [u8] as *const UnsafeCell<[u8]>;
            Builder::from_raw_parts(&*contents, &mut self.context, start)
        }
    }

    /// Build a question.
    ///
    /// If a question is already being built, it will be finished first.  If
    /// an answer, authority, or additional record has been added, [`None`] is
    /// returned instead.
    pub fn build_question<N: BuildIntoMessage>(
        &mut self,
        question: &Question<N>,
    ) -> Result<Option<QuestionBuilder<'_>>, TruncationError> {
        if self.context.state.section_index() > 0 {
            // We've progressed into a later section.
            return Ok(None);
        }

        self.context.state = MessageState::Questions;
        QuestionBuilder::build(self.reborrow(), question).map(Some)
    }

    /// Resume building a question.
    ///
    /// If a question was built (using [`build_question()`]) but the returned
    /// builder was neither committed nor canceled, the question builder will
    /// be recovered and returned.
    ///
    /// [`build_question()`]: Self::build_question()
    pub fn resume_question(&mut self) -> Option<QuestionBuilder<'_>> {
        let MessageState::MidQuestion { name } = self.context.state else {
            return None;
        };

        // SAFETY: 'self.context.state' is synchronized with the message.
        Some(unsafe {
            QuestionBuilder::from_raw_parts(self.reborrow(), name)
        })
    }

    /// Build an answer record.
    ///
    /// If a question or answer is already being built, it will be finished
    /// first.  If an authority or additional record has been added, [`None`]
    /// is returned instead.
    pub fn build_answer(
        &mut self,
        rname: impl BuildIntoMessage,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
    ) -> Result<Option<RecordBuilder<'_>>, TruncationError> {
        if self.context.state.section_index() > 1 {
            // We've progressed into a later section.
            return Ok(None);
        }

        let record = Record {
            rname,
            rtype,
            rclass,
            ttl,
            rdata: &[] as &[u8],
        };

        self.context.state = MessageState::Answers;
        RecordBuilder::build(self.reborrow(), &record).map(Some)
    }

    /// Resume building an answer record.
    ///
    /// If an answer record was built (using [`build_answer()`]) but the
    /// returned builder was neither committed nor canceled, the record
    /// builder will be recovered and returned.
    ///
    /// [`build_answer()`]: Self::build_answer()
    pub fn resume_answer(&mut self) -> Option<RecordBuilder<'_>> {
        let MessageState::MidAnswer { name, data } = self.context.state
        else {
            return None;
        };

        // SAFETY: 'self.context.state' is synchronized with the message.
        Some(unsafe {
            RecordBuilder::from_raw_parts(self.reborrow(), name, data)
        })
    }

    /// Build an authority record.
    ///
    /// If a question, answer, or authority is already being built, it will be
    /// finished first.  If an additional record has been added, [`None`] is
    /// returned instead.
    pub fn build_authority(
        &mut self,
        rname: impl BuildIntoMessage,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
    ) -> Result<Option<RecordBuilder<'_>>, TruncationError> {
        if self.context.state.section_index() > 2 {
            // We've progressed into a later section.
            return Ok(None);
        }

        let record = Record {
            rname,
            rtype,
            rclass,
            ttl,
            rdata: &[] as &[u8],
        };

        self.context.state = MessageState::Authorities;
        RecordBuilder::build(self.reborrow(), &record).map(Some)
    }

    /// Resume building an authority record.
    ///
    /// If an authority record was built (using [`build_authority()`]) but
    /// the returned builder was neither committed nor canceled, the record
    /// builder will be recovered and returned.
    ///
    /// [`build_authority()`]: Self::build_authority()
    pub fn resume_authority(&mut self) -> Option<RecordBuilder<'_>> {
        let MessageState::MidAuthority { name, data } = self.context.state
        else {
            return None;
        };

        // SAFETY: 'self.context.state' is synchronized with the message.
        Some(unsafe {
            RecordBuilder::from_raw_parts(self.reborrow(), name, data)
        })
    }

    /// Build an additional record.
    ///
    /// If a question or record is already being built, it will be finished
    /// first.  Note that it is always possible to add an additional record to
    /// a message.
    pub fn build_additional(
        &mut self,
        rname: impl BuildIntoMessage,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
    ) -> Result<RecordBuilder<'_>, TruncationError> {
        let record = Record {
            rname,
            rtype,
            rclass,
            ttl,
            rdata: &[] as &[u8],
        };

        self.context.state = MessageState::Additionals;
        RecordBuilder::build(self.reborrow(), &record)
    }

    /// Resume building an additional record.
    ///
    /// If an additional record was built (using [`build_additional()`]) but
    /// the returned builder was neither committed nor canceled, the record
    /// builder will be recovered and returned.
    ///
    /// [`build_additional()`]: Self::build_additional()
    pub fn resume_additional(&mut self) -> Option<RecordBuilder<'_>> {
        let MessageState::MidAdditional { name, data } = self.context.state
        else {
            return None;
        };

        // SAFETY: 'self.context.state' is synchronized with the message.
        Some(unsafe {
            RecordBuilder::from_raw_parts(self.reborrow(), name, data)
        })
    }
}
