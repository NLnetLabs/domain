//! A builder for DNS messages.

use core::{
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr::{self, NonNull},
};

use crate::new_base::{
    name::RevName,
    wire::{BuildBytes, ParseBytesByRef, TruncationError},
    Header, Message,
};

use super::BuildCommitted;

//----------- Builder --------------------------------------------------------

/// A DNS wire format serializer.
///
/// This can be used to write arbitrary bytes and (compressed) domain names to
/// a buffer containing a DNS message.  It is a low-level interface, providing
/// the foundations for high-level builder types.
///
/// In order to build a regular DNS message, users would typically look to
/// [`MessageBuilder`](super::MessageBuilder).  This offers the high-level
/// interface (with methods to append questions and records) that most users
/// need.
///
/// # Committing and Delegation
///
/// [`Builder`] provides an "atomic" interface: if a function fails while
/// building a DNS message using a [`Builder`], any partial content added by
/// the [`Builder`] will be reverted.  The content of a [`Builder`] is only
/// confirmed when [`Builder::commit()`] is called.
///
/// It is useful to first describe what "building functions" look like.  While
/// they may take additional arguments, their signatures are usually:
///
/// ```no_run
/// # use domain::new_base::build::{Builder, BuildResult};
///
/// fn foo(mut builder: Builder<'_>) -> BuildResult {
///     // Append to the message using 'builder'.
///
///     // Commit all appended content and return successfully.
///     Ok(builder.commit())
/// }
/// ```
///
/// Note that the builder is taken by value; if an error occurs, and the
/// function returns early, `builder` will be dropped, and its drop code will
/// revert all uncommitted changes.  However, if building is successful, the
/// appended content is committed, and so will not be reverted.
///
/// If `foo` were to call another function with the same signature, it would
/// need to create a new [`Builder`] to pass in by value.  This [`Builder`]
/// should refer to the same message buffer, but should have not report any
/// uncommitted content (so that only the content added by the called function
/// will be reverted on failure).  For this, we have [`delegate()`].
///
/// [`delegate()`]: Self::delegate()
///
/// For example:
///
/// ```
/// # use domain::new_base::build::{Builder, BuildResult, BuilderContext};
///
/// /// A build function with the conventional type signature.
/// fn foo(mut builder: Builder<'_>) -> BuildResult {
///     // Content added by the parent builder is considered committed.
///     assert_eq!(builder.committed(), b"hi! ");
///
///     // Append some content to the builder.
///     builder.append_bytes(b"foo!")?;
///
///     // Try appending a very long string, which can't fit.
///     builder.append_bytes(b"helloworldthisiswaytoobig")?;
///
///     Ok(builder.commit())
/// }
///
/// // Construct a builder for a particular buffer.
/// let mut buffer = [0u8; 20];
/// let mut context = BuilderContext::default();
/// let mut builder = Builder::new(&mut buffer, &mut context);
///
/// // Try appending some content to the builder.
/// builder.append_bytes(b"hi! ").unwrap();
/// assert_eq!(builder.appended(), b"hi! ");
///
/// // Try calling 'foo' -- note that it will fail.
/// // Note that we delegated the builder.
/// foo(builder.delegate()).unwrap_err();
///
/// // No partial content was written.
/// assert_eq!(builder.appended(), b"hi! ");
/// ```
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

/// # Initialization
///
/// In order to begin building a DNS message:
///
/// ```
/// # use domain::new_base::build::{Builder, BuilderContext};
///
/// // Allocate a slice of 'u8's somewhere.
/// let mut buffer = [0u8; 20];
///
/// // Obtain a builder context.
/// //
/// // The value doesn't matter, it will be overwritten.
/// let mut context = BuilderContext::default();
///
/// // Construct the actual 'Builder'.
/// let builder = Builder::new(&mut buffer, &mut context);
///
/// assert!(builder.committed().is_empty());
/// assert!(builder.appended().is_empty());
/// ```
impl<'b> Builder<'b> {
    /// Create a [`Builder`] for a new, empty DNS message.
    ///
    /// The message header is left uninitialized.  Use [`Self::header_mut()`]
    /// to initialize it.  The message contents are completely empty.
    ///
    /// The provided builder context will be overwritten with a default state.
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
            .expect("The buffure must be at least 12 bytes in size");
        context.size = 0;

        // SAFETY: 'message' and 'context' are now consistent.
        unsafe { Self::from_raw_parts(message.into(), context, 0) }
    }

    /// Construct a [`Builder`] from raw parts.
    ///
    /// The provided components must originate from [`into_raw_parts()`], and
    /// none of the components can be modified since they were extracted.
    ///
    /// [`into_raw_parts()`]: Self::into_raw_parts()
    ///
    /// This method is useful when overcoming limitations in lifetimes or
    /// borrow checking, or when a builder has to be constructed from another
    /// with specific characteristics.
    ///
    /// # Safety
    ///
    /// The expression `from_raw_parts(message, context, commit)` is sound if
    /// and only if all of the following conditions are satisfied:
    ///
    /// - `message` is a valid reference for the lifetime `'b`.
    /// - `message.header` is mutably borrowed for `'b`.
    /// - `message.contents[..commit]` is immutably borrowed for `'b`.
    /// - `message.contents[commit..]` is mutably borrowed for `'b`.
    ///
    /// - `message` and `context` originate from the same builder.
    /// - `commit <= context.size() <= message.contents.len()`.
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
}

/// # Inspection
///
/// A [`Builder`] references a message buffer to write into.  That buffer is
/// broken down into the following segments:
///
/// ```text
/// name          | position
/// --------------+---------
/// header        |
/// committed     | 0 .. commit
/// appended      | commit .. size
/// uninitialized | size .. limit
/// inaccessible  | limit ..
/// ```
///
/// The DNS message header can be modified at any time.  It is made available
/// through [`header()`] and [`header_mut()`].  In general, it is inadvisable
/// to change the section counts arbitrarily (although it will not cause
/// undefined behaviour).
///
/// [`header()`]: Self::header()
/// [`header_mut()`]: Self::header_mut()
///
/// The committed content of the builder is immutable, and is available to
/// reference, through [`committed()`], for the lifetime `'b`.
///
/// [`committed()`]: Self::committed()
///
/// The appended content of the builder is made available via [`appended()`].
/// It is content that has been added by this builder, but that has not yet
/// been committed.  When the [`Builder`] is dropped, this content is removed
/// (it becomes uninitialized).  Appended content can be modified, but any
/// compressed names within it have to be handled with great care; they can
/// only be modified by removing them entirely (by rewinding the builder,
/// using [`rewind()`]) and building them again.  When compressed names are
/// guaranteed to not be modified, [`appended_mut()`] can be used.
///
/// [`appended()`]: Self::appended()
/// [`rewind()`]: Self::rewind()
/// [`appended_mut()`]: Self::appended_mut()
///
/// The uninitialized space in the builder will be written to when appending
/// new content.  It can be accessed directly, in case that is more efficient
/// for building, using [`uninitialized()`].  [`mark_appended()`] can be used
/// to specify how many bytes were initialized.
///
/// [`uninitialized()`]: Self::uninitialized()
/// [`mark_appended()`]: Self::mark_appended()
///
/// The inaccessible space of a builder cannot be written to.  While it exists
/// in the underlying message buffer, it has been made inaccessible so that
/// the built message fits within certain size constraints.  A message's size
/// can be limited using [`limit_to()`], but this only applies to the current
/// builder (and its delegates); parent builders are unaffected by it.
///
/// [`limit_to()`]: Self::limit_to()
impl<'b> Builder<'b> {
    /// The header of the DNS message.
    pub fn header(&self) -> &Header {
        // SAFETY: 'message.header' is mutably borrowed by 'self'.
        unsafe { &(*self.message.as_ptr()).header }
    }

    /// The header of the DNS message, mutably.
    ///
    /// It is possible to modify the section counts arbitrarily through this
    /// method; while doing so cannot cause undefined behaviour, it is not
    /// recommended.
    pub fn header_mut(&mut self) -> &mut Header {
        // SAFETY: 'message.header' is mutably borrowed by 'self'.
        unsafe { &mut (*self.message.as_ptr()).header }
    }

    /// Committed message contents.
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
    /// When the first `n` bytes of the returned buffer are initialized, and
    /// should be treated as appended content in the message, call
    /// [`self.mark_appended(n)`](Self::mark_appended()).
    pub fn uninitialized(&mut self) -> &mut [u8] {
        // SAFETY: 'message.contents[commit..]' is mutably borrowed by 'self'.
        unsafe { &mut (*self.message.as_ptr()).contents[self.context.size..] }
    }

    /// The message with all committed contents.
    ///
    /// The header of the message can be modified by the builder, so the
    /// returned reference has a short lifetime.  The message contents can be
    /// borrowed for a longer lifetime -- see [`committed()`].  The message
    /// does not include content that has been appended but not committed.
    ///
    /// [`committed()`]: Self::committed()
    pub fn message(&self) -> &Message {
        // SAFETY: All of 'message' can be immutably borrowed by 'self'.
        unsafe { self.message.as_ref() }.slice_to(self.commit)
    }

    /// The message including any uncommitted contents.
    pub fn cur_message(&self) -> &Message {
        // SAFETY: All of 'message' can be immutably borrowed by 'self'.
        unsafe { self.message.as_ref() }.slice_to(self.context.size)
    }

    /// A pointer to the message, including any uncommitted contents.
    ///
    /// The first `commit` bytes of the message contents (also provided by
    /// [`Self::committed()`]) are immutably borrowed for the lifetime `'b`.
    /// The remainder of the message is initialized and borrowed by `self`.
    pub fn cur_message_ptr(&mut self) -> NonNull<Message> {
        let message = self.message.as_ptr();
        let size = self.context.size;
        let message = unsafe { Message::ptr_slice_to(message, size) };
        unsafe { NonNull::new_unchecked(message) }
    }

    /// The builder context.
    pub fn context(&self) -> &BuilderContext {
        &*self.context
    }

    /// The start point of this builder.
    ///
    /// This is the offset into the message contents at which this builder was
    /// initialized.  The content before this point has been committed and is
    /// immutable.  The builder can be rewound up to this point.
    pub fn start(&self) -> usize {
        self.commit
    }

    /// The size limit of this builder.
    ///
    /// This is the maximum size the message contents can grow to; beyond it,
    /// [`TruncationError`]s will occur.  The limit can be tightened using
    /// [`limit_to()`](Self::limit_to()).
    pub fn max_size(&self) -> usize {
        // SAFETY: 'Message' ends with a slice DST, and so references to it
        // hold the length of that slice; we can cast it to another slice type
        // and the pointer representation is unchanged.  By using a slice type
        // of ZST elements, aliasing is impossible, and it can be dereferenced
        // safely.
        unsafe { &*(self.message.as_ptr() as *mut [()]) }.len()
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

/// # Interaction
///
/// There are several ways to build up a DNS message using a [`Builder`].
///
/// When directly adding content, use [`append_bytes()`] or [`append_name()`].
/// The former will add the bytes as-is, while the latter will compress domain
/// names.
///
/// [`append_bytes()`]: Self::append_bytes()
/// [`append_name()`]: Self::append_name()
///
/// When delegating to another builder method, use [`delegate()`].  This will
/// construct a new [`Builder`] that borrows from the current one.  When the
/// method returns, the content it has committed will be registered as content
/// appended (but not committed) by the outer builder.  If the method fails,
/// any content it tried to add will be removed automatically, and the outer
/// builder will be left unaffected.
///
/// [`delegate()`]: Self::delegate()
///
/// After all data is appended, call [`commit()`].  This will return a marker
/// type, [`BuildCommitted`], that may need to be returned to the caller.
///
/// [`commit()`]: Self::commit()
///
/// Some lower-level building methods are also available in the interest of
/// efficiency.  Use [`append_with()`] if the amount of data to be written is
/// known upfront; it takes a closure to fill that space in the buffer.  The
/// most general and efficient technique is to write into [`uninitialized()`]
/// and to mark the number of initialized bytes using [`mark_appended()`].
///
/// [`append_with()`]: Self::append_with()
/// [`uninitialized()`]: Self::uninitialized()
/// [`mark_appended()`]: Self::mark_appended()
impl Builder<'_> {
    /// Rewind the builder, removing all uncommitted content.
    pub fn rewind(&mut self) {
        self.context.size = self.commit;
    }

    /// Commit the changes made by this builder.
    ///
    /// For convenience, a unit type [`BuildCommitted`] is returned; it is
    /// used as the return type of build functions to remind users to call
    /// this method on success paths.
    pub fn commit(mut self) -> BuildCommitted {
        // Update 'commit' so that the drop glue is a no-op.
        self.commit = self.context.size;
        BuildCommitted
    }

    /// Limit this builder to the given size.
    ///
    /// This builder, and all its delegates, will not allow the message
    /// contents (i.e. excluding the 12-byte message header) to exceed the
    /// specified size in bytes.  If the message has already crossed that
    /// limit, a [`TruncationError`] is returned.
    pub fn limit_to(&mut self, size: usize) -> Result<(), TruncationError> {
        if self.context.size <= size {
            let message = self.message.as_ptr();
            let message = unsafe { Message::ptr_slice_to(message, size) };
            self.message = unsafe { NonNull::new_unchecked(message) };
            Ok(())
        } else {
            Err(TruncationError)
        }
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
        assert!(self.max_size() - self.context.size >= amount);
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

//--- Send, Sync

// SAFETY: The parts of the referenced message that can be accessed mutably
// are not accessible by any reference other than `self`.
unsafe impl Send for Builder<'_> {}

// SAFETY: Only parts of the referenced message that are borrowed immutably
// can be accessed through an immutable reference to `self`.
unsafe impl Sync for Builder<'_> {}

//----------- BuilderContext -------------------------------------------------

/// Context for building a DNS message.
///
/// This type holds auxiliary information necessary for building DNS messages,
/// e.g. name compression state.  To construct it, call [`default()`].
///
/// [`default()`]: Self::default()
#[derive(Clone, Debug, Default)]
pub struct BuilderContext {
    // TODO: Name compression.
    /// The current size of the message contents.
    size: usize,
}
