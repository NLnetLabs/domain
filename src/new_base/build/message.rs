//! Building whole DNS messages.

use core::ptr::NonNull;

use zerocopy::IntoBytes;

use crate::new_base::{
    message::Header,
    question::{QClass, QType, QuestionFields},
    Message, Name,
};

use super::{Builder, BuilderContext, TruncationError};

//----------- MessageBuilder -------------------------------------------------

/// A builder for a whole DNS message.
pub struct MessageBuilder<'b> {
    /// The underlying DNS builder.
    ///
    /// The builder always operates at offset 0.  This ensures that the entire
    /// message is mutably borrowed by the [`MessageBuilder`], allowing it to
    /// perform message truncation.
    inner: Builder<'b>,
}

//--- Construction

impl<'b> MessageBuilder<'b> {
    /// Construct a new [`MessageBuilder`].
    ///
    /// # Safety
    ///
    /// The buffer must point to a valid [`Message`], which is borrowed
    /// mutably for the lifetime `'b`.
    ///
    /// The buffer and context must be associated; they must never be used
    /// with a different context or buffer respectively, or must be reset
    /// before doing so.
    pub unsafe fn from_raw_parts(
        buffer: NonNull<Message>,
        content: &'b mut BuilderContext,
    ) -> Self {
        Self {
            inner: Builder::from_raw_parts(buffer, content, 0),
        }
    }
}

//--- Inspection

impl<'b> MessageBuilder<'b> {
    /// The built message.
    pub fn message(&self) -> &Message {
        self.inner.whole_message()
    }

    /// Access the message header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Access the message header mutably.
    pub fn header_mut(&mut self) -> &mut Header {
        self.inner.header_mut()
    }
}

//--- Interaction

impl<'b> MessageBuilder<'b> {
    /// Append a question.
    ///
    /// # Errors
    ///
    /// If the buffer does not have enough space, [`TruncationError`] is
    /// returned, and no content is appended.
    ///
    /// # Panics
    ///
    /// Panics if the question would have to be inserted in the middle of the
    /// message (i.e. if answer, authority, or additional records have been
    /// appended already).
    pub fn build_question(
        &mut self,
        qname: &Name,
        qtype: QType,
        qclass: QClass,
    ) -> Result<(), TruncationError> {
        let counts = self.header().counts;
        assert!(counts.answers + counts.authorities + counts.additional == 0);

        let mut this = self.delegate();
        this.compress_name(qname)?;
        let fields = QuestionFields { qtype, qclass };
        this.append_bytes(fields.as_bytes())?;
        this.header_mut().counts.questions += 1;
        this.commit();
        Ok(())
    }
}

//--- Low-level interaction

impl<'b> MessageBuilder<'b> {
    /// The total capacity of the message contents.
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Delegate building to a new [`Builder`].
    pub fn delegate(&mut self) -> Builder<'_> {
        self.inner.delegate()
    }

    /// Truncate the message to the given point.
    ///
    /// The specified number of bytes in the message contents will be retained
    /// and the rest will be removed.  The message header will be updated to
    /// mark the message as truncated.
    ///
    /// # Panics
    ///
    /// Panics if there are fewer appended bytes than `amount`.
    pub fn truncate(&mut self, amount: usize) {
        self.inner.rewind_to(amount);
        let header = self.header_mut();
        header.flags = header.flags.set_truncated(true);
    }

    /// Limit the message capacity.
    ///
    /// This can be used to ensure messages beyond a certain size will not be
    /// built, based on e.g. the network MTU.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity is greater than the existing capacity, or
    /// if the new capacity cannot hold the already-built contents.
    pub fn limit_capacity(&mut self, capacity: usize) {
        self.inner.limit_capacity(capacity)
    }
}
