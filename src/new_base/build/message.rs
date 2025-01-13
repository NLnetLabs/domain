//! Building whole DNS messages.

use crate::new_base::{
    wire::TruncationError, Header, Message, Question, RClass, RType, Record,
    TTL,
};

use super::{BuildIntoMessage, Builder, BuilderContext, RecordBuilder};

//----------- MessageBuilder -------------------------------------------------

/// A builder for a whole DNS message.
///
/// This is subtly different from a regular [`Builder`] -- it does not allow
/// for commits and so can always modify the entire message.  It has methods
/// for adding entire questions and records to the message.
pub struct MessageBuilder<'b> {
    /// The underlying [`Builder`].
    ///
    /// Its commit point is always 0.
    inner: Builder<'b>,
}

//--- Initialization

impl<'b> MessageBuilder<'b> {
    /// Construct a [`MessageBuilder`] from raw parts.
    ///
    /// # Safety
    ///
    /// - `message` and `context` are paired together.
    pub unsafe fn from_raw_parts(
        message: &'b mut Message,
        context: &'b mut BuilderContext,
    ) -> Self {
        // SAFETY: since 'commit' is 0, no part of the message is immutably
        // borrowed; it is thus sound to represent as a mutable borrow.
        let inner =
            unsafe { Builder::from_raw_parts(message.into(), context, 0) };
        Self { inner }
    }

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
        let inner = Builder::new(buffer, context);
        Self { inner }
    }
}

//--- Inspection

impl<'b> MessageBuilder<'b> {
    /// The message header.
    ///
    /// The header can be modified by the builder, and so is only available
    /// for a short lifetime.  Note that it implements [`Copy`].
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Mutable access to the message header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.inner.header_mut()
    }

    /// The message built thus far.
    pub fn message(&self) -> &Message {
        self.inner.cur_message()
    }

    /// The message built thus far, mutably.
    ///
    /// # Safety
    ///
    /// The caller must not modify any compressed names among these bytes.
    /// This can invalidate name compression state.
    pub unsafe fn message_mut(&mut self) -> &mut Message {
        // SAFETY: Since no bytes are committed, and the rest of the message
        // is borrowed mutably for 'self', we can use a mutable reference.
        unsafe { self.inner.cur_message_ptr().as_mut() }
    }

    /// The builder context.
    pub fn context(&self) -> &BuilderContext {
        self.inner.context()
    }

    /// Decompose this builder into raw parts.
    ///
    /// This returns the message buffer and the context for this builder.  The
    /// two are linked, and the builder can be recomposed with
    /// [`Self::from_raw_parts()`].
    pub fn into_raw_parts(self) -> (&'b mut Message, &'b mut BuilderContext) {
        let (mut message, context, _commit) = self.inner.into_raw_parts();
        // SAFETY: As per 'Builder::into_raw_parts()', the message is borrowed
        // mutably for the lifetime 'b.  Since the commit point is 0, there is
        // no immutably-borrowed content in the message, so it can be turned
        // into a regular reference.
        (unsafe { message.as_mut() }, context)
    }
}

//--- Interaction

impl MessageBuilder<'_> {
    /// Limit the total message size.
    ///
    /// The message will not be allowed to exceed the given size, in bytes.
    /// Only the message header and contents are counted; the enclosing UDP
    /// or TCP packet size is not considered.  If the message already exceeds
    /// this size, a [`TruncationError`] is returned.
    ///
    /// This size will apply to all builders for this message (including those
    /// that delegated to `self`).  It will not be automatically revoked if
    /// message building fails.
    ///
    /// # Panics
    ///
    /// Panics if the given size is less than 12 bytes.
    pub fn limit_to(&mut self, size: usize) -> Result<(), TruncationError> {
        self.inner.limit_to(size)
    }

    /// Append a question.
    ///
    /// # Panics
    ///
    /// Panics if the message contains any records (as questions must come
    /// before all records).
    pub fn append_question<N>(
        &mut self,
        question: &Question<N>,
    ) -> Result<(), TruncationError>
    where
        N: BuildIntoMessage,
    {
        // Ensure there are no records present.
        assert_eq!(self.header().counts.as_array()[1..], [0, 0, 0]);

        question.build_into_message(self.inner.delegate())?;
        self.header_mut().counts.questions += 1;
        Ok(())
    }

    /// Build an arbitrary record.
    ///
    /// The record will be added to the specified section (1, 2, or 3, i.e.
    /// answers, authorities, and additional records respectively).  There
    /// must not be any existing records in sections after this one.
    pub fn build_record(
        &mut self,
        rname: impl BuildIntoMessage,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
        section: u8,
    ) -> Result<RecordBuilder<'_>, TruncationError> {
        RecordBuilder::new(
            self.inner.delegate(),
            rname,
            rtype,
            rclass,
            ttl,
            section,
        )
    }

    /// Append an answer record.
    ///
    /// # Panics
    ///
    /// Panics if the message contains any authority or additional records.
    pub fn append_answer<N, D>(
        &mut self,
        record: &Record<N, D>,
    ) -> Result<(), TruncationError>
    where
        N: BuildIntoMessage,
        D: BuildIntoMessage,
    {
        // Ensure there are no authority or additional records present.
        assert_eq!(self.header().counts.as_array()[2..], [0, 0]);

        record.build_into_message(self.inner.delegate())?;
        self.header_mut().counts.answers += 1;
        Ok(())
    }

    /// Build an answer record.
    ///
    /// # Panics
    ///
    /// Panics if the message contains any authority or additional records.
    pub fn build_answer(
        &mut self,
        rname: impl BuildIntoMessage,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
    ) -> Result<RecordBuilder<'_>, TruncationError> {
        self.build_record(rname, rtype, rclass, ttl, 1)
    }

    /// Append an authority record.
    ///
    /// # Panics
    ///
    /// Panics if the message contains any additional records.
    pub fn append_authority<N, D>(
        &mut self,
        record: &Record<N, D>,
    ) -> Result<(), TruncationError>
    where
        N: BuildIntoMessage,
        D: BuildIntoMessage,
    {
        // Ensure there are no additional records present.
        assert_eq!(self.header().counts.as_array()[3..], [0]);

        record.build_into_message(self.inner.delegate())?;
        self.header_mut().counts.authorities += 1;
        Ok(())
    }

    /// Build an authority record.
    ///
    /// # Panics
    ///
    /// Panics if the message contains any additional records.
    pub fn build_authority(
        &mut self,
        rname: impl BuildIntoMessage,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
    ) -> Result<RecordBuilder<'_>, TruncationError> {
        self.build_record(rname, rtype, rclass, ttl, 2)
    }

    /// Append an additional record.
    pub fn append_additional<N, D>(
        &mut self,
        record: &Record<N, D>,
    ) -> Result<(), TruncationError>
    where
        N: BuildIntoMessage,
        D: BuildIntoMessage,
    {
        record.build_into_message(self.inner.delegate())?;
        self.header_mut().counts.additional += 1;
        Ok(())
    }

    /// Build an additional record.
    pub fn build_additional(
        &mut self,
        rname: impl BuildIntoMessage,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
    ) -> Result<RecordBuilder<'_>, TruncationError> {
        self.build_record(rname, rtype, rclass, ttl, 3)
    }
}
