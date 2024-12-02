//! Building DNS messages.

use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{self, NonNull},
    slice,
};

use zerocopy::{FromBytes, IntoBytes, SizeError};

use super::{message::Header, Message, Name};

mod message;
pub use message::MessageBuilder;

//----------- Builder --------------------------------------------------------

/// A DNS data builder.
pub struct Builder<'b> {
    /// The message buffer.
    buffer: NonNull<Message>,

    /// Context for building.
    context: &'b mut BuilderContext,

    /// The start of modifiable bytes.
    offset: usize,

    /// The borrowed message buffer.
    _borrow: PhantomData<&'b mut Message>,
}

//--- Construction

impl<'b> Builder<'b> {
    /// Pair a message buffer and building context.
    ///
    /// # Safety
    ///
    /// The buffer must point to a valid [`Message`], which is borrowed
    /// mutably for the lifetime `'b`.
    ///
    /// The offset must refer to a valid offset from the message contents.
    ///
    /// The buffer and context must be associated; they must never be used
    /// with a different context or buffer respectively, or must be reset
    /// before doing so.
    pub unsafe fn from_raw_parts(
        buffer: NonNull<Message>,
        context: &'b mut BuilderContext,
        offset: usize,
    ) -> Self {
        Self {
            buffer,
            context,
            offset,
            _borrow: PhantomData,
        }
    }

    /// Break down a [`Builder`] into its raw parts.
    pub fn into_raw_parts(
        self,
    ) -> (NonNull<Message>, &'b mut BuilderContext, usize) {
        let (buffer, offset) = (self.buffer, self.offset);
        let this = MaybeUninit::new(self);
        // SAFETY: 'this' is definitely initialized.  We move 'context' out of
        // it, which is sound since its drop hook is never run.
        let context =
            unsafe { ptr::read(ptr::addr_of!((*this.as_ptr()).context)) };
        (buffer, context, offset)
    }
}

//--- Inspection

impl<'b> Builder<'b> {
    /// The underlying message buffer.
    pub fn buffer(&self) -> NonNull<Message> {
        self.buffer
    }

    /// The committed message.
    ///
    /// This does not include any uncommitted content.
    pub fn message(&self) -> &Message {
        // Borrow the whole message (including uninitialized space) immutably,
        // then narrow the reference to the correct size.
        let message = unsafe { self.buffer.as_ref() }.as_bytes();
        Message::ref_from_prefix_with_elems(message, self.offset)
            .map_err(SizeError::from)
            .expect("'offset' fits within 'capacity'")
            .0
    }

    /// The built message, including uncommitted content.
    pub fn whole_message(&self) -> &Message {
        // Borrow the whole message (including uninitialized space) immutably,
        // then narrow the reference to the correct size.
        let message = unsafe { self.buffer.as_ref() }.as_bytes();
        Message::ref_from_prefix_with_elems(message, self.context.size)
            .map_err(SizeError::from)
            .expect("'context.size' fits within 'capacity'")
            .0
    }

    /// The message header.
    pub fn header(&self) -> &Header {
        let message = self.buffer.as_ptr();
        // SAFETY: 'buffer' points to a valid, initialized 'Message'.
        unsafe { &*ptr::addr_of!((*message).header) }
    }

    /// Access the message header mutably.
    pub fn header_mut(&mut self) -> &mut Header {
        let message = self.buffer.as_ptr();
        // SAFETY: 'buffer' points to a valid, initialized 'Message'.
        unsafe { &mut *ptr::addr_of_mut!((*message).header) }
    }

    /// Committed message contents.
    pub fn committed(&self) -> &'b [u8] {
        let message = self.buffer.as_ptr();
        // SAFETY: 'buffer' points to a valid, initialized 'Message'.
        let contents = unsafe { ptr::addr_of!((*message).contents) };
        // SAFETY: 'offset' fits within 'contents.len()'.
        unsafe { slice::from_raw_parts(contents.cast(), self.offset) }
    }
}

//--- Interaction

impl<'b> Builder<'b> {
    /// Rewind the builder.
    ///
    /// All appended but uncommitted content will be lost.
    pub fn rewind(&mut self) {
        self.rewind_to(0);
    }

    /// Rewind the builder to a particular point.
    ///
    /// The specified amount of appended (but uncommitted) content will be
    /// retained, while the rest will be removed.
    ///
    /// # Panics
    ///
    /// Panics if there are fewer appended bytes than `amount`.
    pub fn rewind_to(&mut self, amount: usize) {
        // NOTE: 'self.offset <= self.capacity()', thus no overflow.
        assert!(amount <= self.capacity() - self.offset);
        // TODO: Update the name compressor.
        self.context.size = self.offset + amount;
    }

    /// Commit all appended content.
    pub fn commit(&mut self) {
        self.offset = self.context.size;
    }

    /// Delegate building to a new [`Builder`].
    ///
    /// Any content committed by the returned builder will be treated as
    /// appended but uncommitted content by `self`.
    pub fn delegate(&mut self) -> Builder<'_> {
        // SAFETY: 'buffer' and 'context' satisfy the required constraints,
        // since 'self' exists and was constructed from them.  Its methods
        // also maintain those constraints.
        let offset = self.context.size;
        unsafe {
            Builder::from_raw_parts(self.buffer, &mut *self.context, offset)
        }
    }

    /// Append bytes from a slice.
    ///
    /// # Errors
    ///
    /// If there isn't enough space, a [`TruncationError`] is returned.
    pub fn append_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), TruncationError> {
        self.build_bytes(bytes.len(), |space| space.copy_from_slice(bytes))
    }

    /// Build bytes into the buffer.
    ///
    /// The number of bytes to add must be known upfront (otherwise, use
    /// [`uninit_space()`] and [`add_initialized()`]).  A mutable buffer to
    /// those bytes will be provided, which must be filled in.
    ///
    /// [`uninit_space()`]: Self::uninit_space()
    /// [`add_initialized()`]: Self::add_initialized()
    ///
    /// # Errors
    ///
    /// If there isn't enough space, a [`TruncationError`] is returned.
    pub fn build_bytes(
        &mut self,
        amount: usize,
        builder: impl FnOnce(&mut [u8]),
    ) -> Result<(), TruncationError> {
        self.uninit_space()
            .get_mut(..amount)
            .map(builder)
            .ok_or(TruncationError)
    }

    /// Compress and append a name to the message.
    ///
    /// # Errors
    ///
    /// If there isn't enough space, a [`TruncationError`] is returned.
    pub fn compress_name(
        &mut self,
        name: &Name,
    ) -> Result<(), TruncationError> {
        // TODO: Implement name compression.
        self.append_bytes(name.as_bytes())
    }
}

//--- Low-level interaction

impl<'b> Builder<'b> {
    /// The total capacity of the message contents.
    pub fn capacity(&self) -> usize {
        let message = self.buffer.as_ptr();
        // SAFETY: 'buffer' points to a valid, initialized 'Message'.
        let contents = unsafe { ptr::addr_of!((*message).contents) };
        contents.len()
    }

    /// Uninitialized space in the message buffer.
    ///
    /// Data written here can be initialized using [`add_initialized()`].
    ///
    /// [`add_initialized()`]: Self::add_initialized()
    pub fn uninit_space(&mut self) -> &mut [u8] {
        let message = self.buffer.as_ptr();
        // SAFETY: 'buffer' points to a valid, initialized 'Message'.
        let contents = unsafe { ptr::addr_of_mut!((*message).contents) };
        // SAFETY: 'size' is at most 'contents.len()'.
        let ptr = unsafe { contents.cast::<u8>().add(self.context.size) };
        let len = contents.len() - self.context.size;
        // SAFETY: 'contents[size..]' is not currently borrowed.
        unsafe { slice::from_raw_parts_mut(ptr, len) }
    }

    /// Mark bytes as initialized.
    ///
    /// These bytes should be written using [`uninit_space()`] before being
    /// marked as initialized.  Otherwise, their contents are undefined (but
    /// not uninitialized).
    ///
    /// [`uninit_space()`]: Self::uninit_space()
    ///
    /// # Panics
    ///
    /// Panics if more than `uninit_space().len()` bytes are added.
    pub fn add_initialized(&mut self, amount: usize) {
        // NOTE: 'self.context.size <= self.capacity()', thus no overflow.
        assert!(amount <= self.capacity() - self.context.size);
        self.context.size += amount;
    }

    /// Limit the builder's capacity.
    ///
    /// This can be used to ensure messages beyond a certain size will not be
    /// built, based on e.g. the network MTU.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity is greater than the existing capacity, or
    /// if the new capacity cannot hold the already-built contents.
    pub fn limit_capacity(&mut self, capacity: usize) {
        assert!(capacity < self.capacity());
        assert!(self.context.size <= capacity);

        // NOTE: This would be cleaner if 'zerocopy' offered ptr-based fns.
        let message = unsafe { self.buffer.as_ref() }.as_bytes();
        let message = Message::ref_from_prefix_with_elems(message, capacity)
            .map_err(SizeError::from)
            .expect("'offset' fits within 'capacity'")
            .0;
        self.buffer = message.into();
    }
}

//--- Drop

impl<'b> Drop for Builder<'b> {
    fn drop(&mut self) {
        // Drop any uncommitted content.
        self.rewind();
    }
}

//----------- BuilderContext -------------------------------------------------

/// Context for building DNS messages.
pub struct BuilderContext {
    /// The current size of the message.
    pub size: usize,
    // TODO: Name compression.
}

//----------- TruncationError ------------------------------------------------

/// A truncation error.
///
/// This occurs when content cannot be appended to a message because it would
/// become too big.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TruncationError;
