//! A builder for DNS messages.

use core::{
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr::{self, NonNull},
};

use crate::new_base::{
    name::RevName,
    wire::{AsBytes, BuildBytes, ParseBytesByRef, TruncationError},
    Header, Message,
};

use super::BuildCommitted;

//----------- Builder --------------------------------------------------------

/// A DNS message builder.
pub struct Builder<'b> {
    /// The message being built.
    ///
    /// The message is divided into four parts:
    ///
    /// - The message header (borrowed mutably by this type).
    /// - Committed message contents (borrowed *immutably* by this type).
    /// - Appended message contents (borrowed mutably by this type).
    /// - Uninitialized message contents (borrowed mutably by this type).
    message: NonNull<Message>,

    _message: PhantomData<&'b mut Message>,

    /// Context for building.
    context: &'b mut BuilderContext,

    /// The commit point of this builder.
    ///
    /// Message contents up to this point are committed and cannot be removed
    /// by this builder.  Message contents following this (up to the size in
    /// the builder context) are appended but uncommitted.
    commit: usize,
}

//--- Initialization

impl<'b> Builder<'b> {
    /// Construct a [`Builder`] from raw parts.
    ///
    /// # Safety
    ///
    /// - `message` is a valid reference for the lifetime `'b`.
    /// - `message.header` is mutably borrowed for `'b`.
    /// - `message.contents[..commit]` is immutably borrowed for `'b`.
    /// - `message.contents[commit..]` is mutably borrowed for `'b`.
    ///
    /// - `message` and `context` are paired together.
    ///
    /// - `commit` is at most `context.size()`, which is at most
    ///   `context.max_size()`.
    pub unsafe fn from_raw_parts(
        message: NonNull<Message>,
        context: &'b mut BuilderContext,
        commit: usize,
    ) -> Self {
        Self {
            message,
            _message: PhantomData,
            context,
            commit,
        }
    }

    /// Initialize an empty [`Builder`].
    ///
    /// The message header is left uninitialized.  Use [`Self::header_mut()`]
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
        assert!(buffer.len() >= 12);
        let message = Message::parse_bytes_by_mut(buffer)
            .expect("A 'Message' can fit in 12 bytes");
        context.size = 0;
        context.max_size = message.contents.len();

        // SAFETY: 'message' and 'context' are now consistent.
        unsafe { Self::from_raw_parts(message.into(), context, 0) }
    }
}

//--- Inspection

impl<'b> Builder<'b> {
    /// The message header.
    ///
    /// The header can be modified by the builder, and so is only available
    /// for a short lifetime.  Note that it implements [`Copy`].
    pub fn header(&self) -> &Header {
        // SAFETY: 'message.header' is mutably borrowed by 'self'.
        unsafe { &(*self.message.as_ptr()).header }
    }

    /// Mutable access to the message header.
    pub fn header_mut(&mut self) -> &mut Header {
        // SAFETY: 'message.header' is mutably borrowed by 'self'.
        unsafe { &mut (*self.message.as_ptr()).header }
    }

    /// Committed message contents.
    ///
    /// The message contents are available for the lifetime `'b`; the builder
    /// cannot be used to modify them since they have been committed.
    pub fn committed(&self) -> &'b [u8] {
        // SAFETY: 'message.contents[..commit]' is immutably borrowed by
        // 'self'.
        unsafe { &(*self.message.as_ptr()).contents[..self.commit] }
    }

    /// The appended but uncommitted contents of the message.
    ///
    /// The builder can modify or rewind these contents, so they are offered
    /// with a short lifetime.
    pub fn appended(&self) -> &[u8] {
        // SAFETY: 'message.contents[commit..]' is mutably borrowed by 'self'.
        let range = self.commit..self.context.size;
        unsafe { &(*self.message.as_ptr()).contents[range] }
    }

    /// The appended but uncommitted contents of the message, mutably.
    ///
    /// # Safety
    ///
    /// The caller must not modify any compressed names among these bytes.
    /// This can invalidate name compression state.
    pub unsafe fn appended_mut(&mut self) -> &mut [u8] {
        // SAFETY: 'message.contents[commit..]' is mutably borrowed by 'self'.
        let range = self.commit..self.context.size;
        unsafe { &mut (*self.message.as_ptr()).contents[range] }
    }

    /// Uninitialized space in the message buffer.
    ///
    /// This can be filled manually, then marked as initialized using
    /// [`Self::mark_appended()`].
    pub fn uninitialized(&mut self) -> &mut [u8] {
        // SAFETY: 'message.contents[commit..]' is mutably borrowed by 'self'.
        let range = self.context.size..self.context.max_size;
        unsafe { &mut (*self.message.as_ptr()).contents[range] }
    }

    /// The message with all committed contents.
    ///
    /// The header of the message can be modified by the builder, so the
    /// returned reference has a short lifetime.  The message contents can be
    /// borrowed for a longer lifetime -- see [`Self::committed()`].
    pub fn message(&self) -> &Message {
        // SAFETY: All of 'message' can be immutably borrowed by 'self'.
        let message = unsafe { &*self.message.as_ptr() };
        let message = &message.as_bytes()[..12 + self.commit];
        Message::parse_bytes_by_ref(message)
            .expect("'message' represents a valid 'Message'")
    }

    /// The message including any uncommitted contents.
    ///
    /// The header of the message can be modified by the builder, so the
    /// returned reference has a short lifetime.  The message contents can be
    /// borrowed for a longer lifetime -- see [`Self::committed()`].
    pub fn cur_message(&self) -> &Message {
        // SAFETY: All of 'message' can be immutably borrowed by 'self'.
        let message = unsafe { &*self.message.as_ptr() };
        let message = &message.as_bytes()[..12 + self.context.size];
        Message::parse_bytes_by_ref(message)
            .expect("'message' represents a valid 'Message'")
    }

    /// A pointer to the message, including any uncommitted contents.
    ///
    /// The first `commit` bytes of the message contents (also provided by
    /// [`Self::committed()`]) are immutably borrowed for the lifetime `'b`.
    /// The remainder of the message is initialized and borrowed by `self`.
    pub fn cur_message_ptr(&self) -> NonNull<Message> {
        self.cur_message().into()
    }

    /// The builder context.
    pub fn context(&self) -> &BuilderContext {
        &*self.context
    }

    /// Decompose this builder into raw parts.
    ///
    /// This returns three components:
    ///
    /// - The message buffer.  The committed contents of the message (the
    ///   first `commit` bytes of the message contents) are borrowed immutably
    ///   for the lifetime `'b`.  The remainder of the message buffer is
    ///   borrowed mutably for the lifetime `'b`.
    ///
    /// - Context for this builder.
    ///
    /// - The amount of data committed in the message (`commit`).
    ///
    /// The builder can be recomposed with [`Self::from_raw_parts()`].
    pub fn into_raw_parts(
        self,
    ) -> (NonNull<Message>, &'b mut BuilderContext, usize) {
        // NOTE: The context has to be moved out carefully.
        let (message, commit) = (self.message, self.commit);
        let this = ManuallyDrop::new(self);
        let this = (&*this) as *const Self;
        // SAFETY: 'this' is a valid object that can be moved out of.
        let context = unsafe { ptr::read(ptr::addr_of!((*this).context)) };
        (message, context, commit)
    }
}

//--- Interaction

impl Builder<'_> {
    /// Rewind the builder, removing all committed content.
    pub fn rewind(&mut self) {
        self.context.size = self.commit;
    }

    /// Commit all appended content.
    ///
    /// For convenience, a unit type [`BuildCommitted`] is returned; it is
    /// used as the return type of build functions to remind users to call
    /// this method on success paths.
    pub fn commit(&mut self) -> BuildCommitted {
        self.commit = self.context.size;
        BuildCommitted
    }

    /// Mark bytes in the buffer as initialized.
    ///
    /// The given number of bytes from the beginning of
    /// [`Self::uninitialized()`] will be marked as initialized, and will be
    /// treated as appended content in the buffer.
    ///
    /// # Panics
    ///
    /// Panics if the uninitialized buffer is smaller than the given number of
    /// initialized bytes.
    pub fn mark_appended(&mut self, amount: usize) {
        assert!(self.context.max_size - self.context.size >= amount);
        self.context.size += amount;
    }

    /// Delegate to a new builder.
    ///
    /// Any content committed by the builder will be added as uncommitted
    /// content for this builder.
    pub fn delegate(&mut self) -> Builder<'_> {
        let commit = self.context.size;
        unsafe {
            Builder::from_raw_parts(self.message, &mut *self.context, commit)
        }
    }

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
        assert!(size >= 12);
        if self.context.size <= size - 12 {
            self.context.max_size = size - 12;
            Ok(())
        } else {
            Err(TruncationError)
        }
    }

    /// Append data of a known size using a closure.
    ///
    /// All the requested bytes must be initialized.  If not enough free space
    /// could be obtained, a [`TruncationError`] is returned.
    pub fn append_with(
        &mut self,
        size: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<(), TruncationError> {
        self.uninitialized()
            .get_mut(..size)
            .ok_or(TruncationError)
            .map(fill)
            .map(|()| self.context.size += size)
    }

    /// Append some bytes.
    ///
    /// No name compression will be performed.
    pub fn append_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), TruncationError> {
        self.append_with(bytes.len(), |buffer| buffer.copy_from_slice(bytes))
    }

    /// Compress and append a domain name.
    pub fn append_name(
        &mut self,
        name: &RevName,
    ) -> Result<(), TruncationError> {
        // TODO: Perform name compression.
        name.build_bytes(self.uninitialized())?;
        self.mark_appended(name.len());
        Ok(())
    }
}

//--- Drop

impl Drop for Builder<'_> {
    fn drop(&mut self) {
        // Drop uncommitted content.
        self.rewind();
    }
}

//----------- BuilderContext -------------------------------------------------

/// Context for building a DNS message.
#[derive(Clone, Debug)]
pub struct BuilderContext {
    // TODO: Name compression.
    /// The current size of the message contents.
    size: usize,

    /// The maximum size of the message contents.
    max_size: usize,
}

//--- Inspection

impl BuilderContext {
    /// The size of the message contents.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The maximum size of the message contents.
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

//--- Default

impl Default for BuilderContext {
    fn default() -> Self {
        Self {
            size: 0,
            max_size: 65535 - core::mem::size_of::<Header>(),
        }
    }
}
