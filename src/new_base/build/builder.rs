//! A builder for DNS messages.

use core::{
    cell::UnsafeCell,
    mem::ManuallyDrop,
    ptr::{self},
    slice,
};

use crate::new_base::{
    name::RevName,
    wire::{BuildBytes, TruncationError},
};

use super::{BuildCommitted, BuilderContext};

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
pub struct Builder<'b> {
    /// The contents of the built message.
    ///
    /// The buffer is divided into three parts:
    ///
    /// - Committed message contents (borrowed *immutably* by this type).
    /// - Appended message contents (borrowed mutably by this type).
    /// - Uninitialized message contents (borrowed mutably by this type).
    contents: &'b UnsafeCell<[u8]>,

    /// Context for building.
    context: &'b mut BuilderContext,

    /// The start point of this builder.
    ///
    /// Message contents up to this point are committed and cannot be removed
    /// by this builder.  Message contents following this (up to the size in
    /// the builder context) are appended but uncommitted.
    start: usize,
}

impl<'b> Builder<'b> {
    /// Construct a [`Builder`] from raw parts.
    ///
    /// # Safety
    ///
    /// The expression `from_raw_parts(contents, context, start)` is sound if
    /// and only if all of the following conditions are satisfied:
    ///
    /// - `message[..start]` is immutably borrowed for `'b`.
    /// - `message[start..]` is mutably borrowed for `'b`.
    ///
    /// - `message` and `context` originate from the same builder.
    /// - `start <= context.size() <= message.len()`.
    pub unsafe fn from_raw_parts(
        contents: &'b UnsafeCell<[u8]>,
        context: &'b mut BuilderContext,
        start: usize,
    ) -> Self {
        Self {
            contents,
            context,
            start,
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
/// committed     | 0 .. start
/// appended      | start .. offset
/// uninitialized | offset .. limit
/// inaccessible  | limit ..
/// ```
///
/// The committed content of the builder is immutable, and is available to
/// reference, through [`committed()`], for the lifetime `'b`.
///
/// [`committed()`]: Self::committed()
///
/// The appended but uncommitted content of the builder is made available via
/// [`uncommitted_mut()`].  It is content that has been added by this builder,
/// but that has not yet been committed.  When the [`Builder`] is dropped,
/// this content is removed (it becomes uninitialized).  Appended content can
/// be modified, but any compressed names within it have to be handled with
/// great care; they can only be modified by removing them entirely (by
/// rewinding the builder, using [`rewind()`]) and building them again.  When
/// compressed names are guaranteed to not be modified, [`uncommitted_mut()`]
/// can be used.
///
/// [`appended()`]: Self::appended()
/// [`rewind()`]: Self::rewind()
/// [`uncommitted_mut()`]: Self::uncommitted_mut()
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
    /// Committed message contents.
    pub fn committed(&self) -> &'b [u8] {
        let message = self.contents.get().cast_const().cast();
        // SAFETY: 'message[..start]' is immutably borrowed.
        unsafe { slice::from_raw_parts(message, self.start) }
    }

    /// Appended (and committed) message contents.
    pub fn appended(&self) -> &[u8] {
        let message = self.contents.get().cast_const().cast();
        // SAFETY: 'message[..offset]' is (im)mutably borrowed.
        unsafe { slice::from_raw_parts(message, self.context.size) }
    }

    /// The appended but uncommitted contents of the message.
    ///
    /// The builder can modify or rewind these contents, so they are offered
    /// with a short lifetime.
    pub fn uncommitted(&self) -> &[u8] {
        let message = self.contents.get().cast::<u8>().cast_const();
        // SAFETY: It is guaranteed that 'start <= message.len()'.
        let message = unsafe { message.add(self.start) };
        let size = self.context.size - self.start;
        // SAFETY: 'message[start..]' is mutably borrowed.
        unsafe { slice::from_raw_parts(message, size) }
    }

    /// The appended but uncommitted contents of the message, mutably.
    ///
    /// # Safety
    ///
    /// The caller must not modify any compressed names among these bytes.
    /// This can invalidate name compression state.
    pub unsafe fn uncommitted_mut(&mut self) -> &mut [u8] {
        let message = self.contents.get().cast::<u8>();
        // SAFETY: It is guaranteed that 'start <= message.len()'.
        let message = unsafe { message.add(self.start) };
        let size = self.context.size - self.start;
        // SAFETY: 'message[start..]' is mutably borrowed.
        unsafe { slice::from_raw_parts_mut(message, size) }
    }

    /// Uninitialized space in the message buffer.
    ///
    /// When the first `n` bytes of the returned buffer are initialized, and
    /// should be treated as appended content in the message, call
    /// [`self.mark_appended(n)`](Self::mark_appended()).
    pub fn uninitialized(&mut self) -> &mut [u8] {
        let message = self.contents.get().cast::<u8>();
        // SAFETY: It is guaranteed that 'size <= message.len()'.
        let message = unsafe { message.add(self.context.size) };
        let size = self.max_size() - self.context.size;
        // SAFETY: 'message[size..]' is mutably borrowed.
        unsafe { slice::from_raw_parts_mut(message, size) }
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
        self.start
    }

    /// The append point of this builder.
    ///
    /// This is the offset into the message contents at which new data will be
    /// written.  The content after this point is uninitialized.
    pub fn offset(&self) -> usize {
        self.context.size
    }

    /// The size limit of this builder.
    ///
    /// This is the maximum size the message contents can grow to; beyond it,
    /// [`TruncationError`]s will occur.  The limit can be tightened using
    /// [`limit_to()`](Self::limit_to()).
    pub fn max_size(&self) -> usize {
        // SAFETY: We can cast 'contents' to another slice type and the
        // pointer representation is unchanged.  By using a slice type of ZST
        // elements, aliasing is impossible, and it can be dereferenced
        // safely.
        unsafe { &*(self.contents.get() as *mut [()]) }.len()
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
    ) -> (&'b UnsafeCell<[u8]>, &'b mut BuilderContext, usize) {
        // NOTE: The context has to be moved out carefully.
        let (contents, start) = (self.contents, self.start);
        let this = ManuallyDrop::new(self);
        let this = (&*this) as *const Self;
        // SAFETY: 'this' is a valid object that can be moved out of.
        let context = unsafe { ptr::read(ptr::addr_of!((*this).context)) };
        (contents, context, start)
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
        self.context.size = self.start;
    }

    /// Commit the changes made by this builder.
    ///
    /// For convenience, a unit type [`BuildCommitted`] is returned; it is
    /// used as the return type of build functions to remind users to call
    /// this method on success paths.
    pub fn commit(mut self) -> BuildCommitted {
        // Update 'commit' so that the drop glue is a no-op.
        self.start = self.context.size;
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
            let message = self.contents.get().cast::<u8>();
            debug_assert!(size <= self.max_size());
            self.contents = unsafe {
                &*(ptr::slice_from_raw_parts_mut(message, size) as *const _)
            };
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
            Builder::from_raw_parts(self.contents, &mut *self.context, commit)
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

    /// Serialize an object into bytes and append it.
    ///
    /// No name compression will be performed.
    pub fn append_built_bytes(
        &mut self,
        object: &impl BuildBytes,
    ) -> Result<(), TruncationError> {
        let rest = object.build_bytes(self.uninitialized())?.len();
        let appended = self.uninitialized().len() - rest;
        self.mark_appended(appended);
        Ok(())
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
