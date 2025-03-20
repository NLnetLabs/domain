//! Building whole DNS messages.

use core::cell::UnsafeCell;

use crate::new_base::{
    wire::{ParseBytesByRef, TruncationError},
    Header, Message, Question, Record,
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
pub struct MessageBuilder<'b, 'c> {
    /// The message being constructed.
    pub(super) message: &'b mut Message,

    /// Context for building.
    pub(super) context: &'c mut BuilderContext,
}

//--- Initialization

impl<'b, 'c> MessageBuilder<'b, 'c> {
    /// Initialize an empty [`MessageBuilder`].
    ///
    /// The message header is left uninitialized.  use [`Self::header_mut()`]
    /// to initialize it.
    ///
    /// # Panics
    ///
    /// Panics if the buffer is less than 12 bytes long (which is the minimum
    /// possible size for a DNS message).
    #[must_use]
    pub fn new(
        buffer: &'b mut [u8],
        context: &'c mut BuilderContext,
    ) -> Self {
        let message = Message::parse_bytes_by_mut(buffer)
            .expect("The caller's buffer is at least 12 bytes big");
        *context = BuilderContext::default();
        Self { message, context }
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
        self.message.slice_to(self.context.size)
    }

    /// The message built thus far, mutably.
    ///
    /// # Safety
    ///
    /// The caller must not modify any compressed names among these bytes.
    /// This can invalidate name compression state.
    #[must_use]
    pub unsafe fn message_mut(&mut self) -> &mut Message {
        self.message.slice_to_mut(self.context.size)
    }

    /// The builder context.
    #[must_use]
    pub fn context(&self) -> &BuilderContext {
        self.context
    }
}

//--- Interaction

impl<'b> MessageBuilder<'b, '_> {
    /// End the builder, returning the built message.
    ///
    /// The returned message is valid, but it can be modified by the caller
    /// arbitrarily; avoid modifying the message beyond the header.
    #[must_use]
    pub fn finish(self) -> &'b mut Message {
        self.message.slice_to_mut(self.context.size)
    }

    /// Reborrow the builder with a shorter lifetime.
    #[must_use]
    pub fn reborrow(&mut self) -> MessageBuilder<'_, '_> {
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
    #[must_use]
    pub(super) fn builder(&mut self, start: usize) -> Builder<'_> {
        debug_assert!(start <= self.context.size);
        unsafe {
            let contents = &mut self.message.contents;
            let contents = contents as *mut [u8] as *const UnsafeCell<[u8]>;
            Builder::from_raw_parts(&*contents, self.context, start)
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
        let state = &mut self.context.state;
        if state.section_index() > 0 {
            // We've progressed into a later section.
            return Ok(None);
        }

        if state.mid_component() {
            let index = state.section_index() as usize;
            self.message.header.counts.as_array_mut()[index] += 1;
        }

        *state = MessageState::Questions;
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
    pub fn build_answer<N: BuildIntoMessage, D: BuildIntoMessage>(
        &mut self,
        record: &Record<N, D>,
    ) -> Result<Option<RecordBuilder<'_>>, TruncationError> {
        let state = &mut self.context.state;
        if state.section_index() > 1 {
            // We've progressed into a later section.
            return Ok(None);
        }

        if state.mid_component() {
            let index = state.section_index() as usize;
            self.message.header.counts.as_array_mut()[index] += 1;
        }

        *state = MessageState::Answers;
        RecordBuilder::build(self.reborrow(), record).map(Some)
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
    pub fn build_authority<N: BuildIntoMessage, D: BuildIntoMessage>(
        &mut self,
        record: &Record<N, D>,
    ) -> Result<Option<RecordBuilder<'_>>, TruncationError> {
        let state = &mut self.context.state;
        if state.section_index() > 2 {
            // We've progressed into a later section.
            return Ok(None);
        }

        if state.mid_component() {
            let index = state.section_index() as usize;
            self.message.header.counts.as_array_mut()[index] += 1;
        }

        *state = MessageState::Authorities;
        RecordBuilder::build(self.reborrow(), record).map(Some)
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
    pub fn build_additional<N: BuildIntoMessage, D: BuildIntoMessage>(
        &mut self,
        record: &Record<N, D>,
    ) -> Result<RecordBuilder<'_>, TruncationError> {
        let state = &mut self.context.state;
        if state.mid_component() {
            let index = state.section_index() as usize;
            self.message.header.counts.as_array_mut()[index] += 1;
        }

        *state = MessageState::Additionals;
        RecordBuilder::build(self.reborrow(), record)
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

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use crate::{
        new_base::{
            build::{BuilderContext, MessageState},
            name::RevName,
            wire::U16,
            QClass, QType, Question, RClass, RType, Record, SectionCounts,
            TTL,
        },
        new_rdata::A,
    };

    use super::MessageBuilder;

    const WWW_EXAMPLE_ORG: &RevName = unsafe {
        RevName::from_bytes_unchecked(b"\x00\x03org\x07example\x03www")
    };

    #[test]
    fn new() {
        let mut buffer = [0u8; 12];
        let mut context = BuilderContext::default();

        let mut builder = MessageBuilder::new(&mut buffer, &mut context);

        assert_eq!(&builder.message().contents, &[] as &[u8]);
        assert_eq!(unsafe { &builder.message_mut().contents }, &[] as &[u8]);
        assert_eq!(builder.context().size, 0);
        assert_eq!(builder.context().state, MessageState::Questions);
    }

    #[test]
    fn build_question() {
        let mut buffer = [0u8; 33];
        let mut context = BuilderContext::default();
        let mut builder = MessageBuilder::new(&mut buffer, &mut context);

        let question = Question {
            qname: WWW_EXAMPLE_ORG,
            qtype: QType::A,
            qclass: QClass::IN,
        };
        let qb = builder.build_question(&question).unwrap().unwrap();

        assert_eq!(qb.qname().as_bytes(), b"\x03www\x07example\x03org\x00");
        assert_eq!(qb.qtype(), question.qtype);
        assert_eq!(qb.qclass(), question.qclass);

        let state = MessageState::MidQuestion { name: 0 };
        assert_eq!(builder.context().state, state);
        assert_eq!(builder.message().header.counts, SectionCounts::default());
        let contents = b"\x03www\x07example\x03org\x00\x00\x01\x00\x01";
        assert_eq!(&builder.message().contents, contents);
    }

    #[test]
    fn resume_question() {
        let mut buffer = [0u8; 33];
        let mut context = BuilderContext::default();
        let mut builder = MessageBuilder::new(&mut buffer, &mut context);

        let question = Question {
            qname: WWW_EXAMPLE_ORG,
            qtype: QType::A,
            qclass: QClass::IN,
        };
        let _ = builder.build_question(&question).unwrap().unwrap();

        let qb = builder.resume_question().unwrap();
        assert_eq!(qb.qname().as_bytes(), b"\x03www\x07example\x03org\x00");
        assert_eq!(qb.qtype(), question.qtype);
        assert_eq!(qb.qclass(), question.qclass);

        qb.commit();
        assert_eq!(
            builder.message().header.counts,
            SectionCounts {
                questions: U16::new(1),
                ..Default::default()
            }
        );
    }

    #[test]
    fn build_record() {
        let mut buffer = [0u8; 43];
        let mut context = BuilderContext::default();
        let mut builder = MessageBuilder::new(&mut buffer, &mut context);

        let record = Record {
            rname: WWW_EXAMPLE_ORG,
            rtype: RType::A,
            rclass: RClass::IN,
            ttl: TTL::from(42),
            rdata: b"",
        };

        {
            let mut rb = builder.build_answer(&record).unwrap().unwrap();

            assert_eq!(
                rb.rname().as_bytes(),
                b"\x03www\x07example\x03org\x00"
            );
            assert_eq!(rb.rtype(), record.rtype);
            assert_eq!(rb.rclass(), record.rclass);
            assert_eq!(rb.ttl(), record.ttl);
            assert_eq!(rb.rdata(), b"");

            assert!(rb.delegate().append_bytes(&[0u8; 5]).is_err());

            {
                let mut builder = rb.delegate();
                builder
                    .append_built_bytes(&A {
                        octets: [127, 0, 0, 1],
                    })
                    .unwrap();
                builder.commit();
            }
            assert_eq!(rb.rdata(), b"\x7F\x00\x00\x01");
        }

        let state = MessageState::MidAnswer { name: 0, data: 27 };
        assert_eq!(builder.context().state, state);
        assert_eq!(builder.message().header.counts, SectionCounts::default());
        let contents = b"\x03www\x07example\x03org\x00\x00\x01\x00\x01\x00\x00\x00\x2A\x00\x04\x7F\x00\x00\x01";
        assert_eq!(&builder.message().contents, contents.as_slice());
    }

    #[test]
    fn resume_record() {
        let mut buffer = [0u8; 39];
        let mut context = BuilderContext::default();
        let mut builder = MessageBuilder::new(&mut buffer, &mut context);

        let record = Record {
            rname: WWW_EXAMPLE_ORG,
            rtype: RType::A,
            rclass: RClass::IN,
            ttl: TTL::from(42),
            rdata: b"",
        };
        let _ = builder.build_answer(&record).unwrap().unwrap();

        let rb = builder.resume_answer().unwrap();
        assert_eq!(rb.rname().as_bytes(), b"\x03www\x07example\x03org\x00");
        assert_eq!(rb.rtype(), record.rtype);
        assert_eq!(rb.rclass(), record.rclass);
        assert_eq!(rb.ttl(), record.ttl);
        assert_eq!(rb.rdata(), b"");

        rb.commit();
        assert_eq!(
            builder.message().header.counts,
            SectionCounts {
                answers: U16::new(1),
                ..Default::default()
            }
        );
    }
}
