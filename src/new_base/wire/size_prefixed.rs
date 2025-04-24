//! Working with (U16-)size-prefixed data.

use core::{
    borrow::{Borrow, BorrowMut},
    cmp::Ordering,
    fmt,
    ops::{Deref, DerefMut},
};

use domain_macros::UnsizedCopy;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
};

use super::{
    AsBytes, BuildBytes, ParseBytes, ParseBytesZC, ParseError, SplitBytes,
    SplitBytesZC, TruncationError,
};

//----------- SizePrefixed ---------------------------------------------------

/// A wrapper adding a size prefix during serialization.
///
/// DNS messages often contain size-prefixed data.  Record data is prefixed by
/// a [`U16`](super::U16), indicating its size in bytes, and NSEC3 salts are
/// prefixed by a [`u8`] with the same meaning.  [`SizePrefixed`] wraps such
/// data and handles the logic for (de)serialization.
///
/// *Warning:* in order to implement zero-copy (de)serialization, this type
/// has a `size` field which always holds the size of `T` (or the size of the
/// currently stored object, if `T` is `?Sized`).  If this size overflows `S`,
/// a panic will occur.  This can occur even if `T` is only used serialized
/// via [`ParseBytes`] / [`BuildBytes`], which don't use the `size` field.
/// Thus, a 300-byte `T` cannot be used with a `u8` size prefix, even if the
/// `T` serializes into 20 bytes.  This almost never occurs in practice.
///
/// ## Bounds
///
/// `S` must satisfy various bounds for use in (de)serialization.
///
/// - `S` should almost always implement `TryFrom<usize>`.  This is needed to
///   initialize it manually, e.g. from the size of `T`.  It can be omitted
///   for the zero-copy traits [`ParseBytesZC`], [`SplitBytesZC`], and
///   [`AsBytes`].
///
/// - During parsing, `S` should implement [`SplitMessageBytes`],
///   [`SplitBytes`], or [`SplitBytesZC`].  It should also implement
///   `Into<usize>`; this is used to read the right number of bytes for the
///   actual size-prefixed data.
///
/// - During building, `S` should implement [`BuildIntoMessage`],
///   [`BuildBytes`], or [`AsBytes`].  For the first two, it should also
///   implement [`Default`]; this is used to temporarily initialize it, to be
///   overwritten once the actual size-prefixed data is built (and its size is
///   determined).
#[derive(Copy, Clone, AsBytes, UnsizedCopy)]
#[repr(C)]
pub struct SizePrefixed<S, T: ?Sized> {
    /// The size prefix (needed for 'ParseBytesZC' / 'AsBytes').
    ///
    /// This field is only used by the zero-copy (de)serialization traits.  As
    /// such, this field should always be consistent with the size of `data`.
    size: S,

    /// The inner data.
    data: T,
}

//--- Construction

impl<S, T> SizePrefixed<S, T>
where
    S: TryFrom<usize>,
{
    /// Construct a [`SizePrefixed`].
    ///
    /// # Panics
    ///
    /// Panics if the size of `data` in memory cannot fit in `S`.  This is
    /// necessary for `SizePrefixed` to correctly implement [`AsBytes`] and
    /// [`ParseBytesZC`] / [`SplitBytesZC`].
    pub fn new(data: T) -> Self {
        let size = core::mem::size_of::<T>();
        Self {
            size: S::try_from(size).unwrap_or_else(|_| {
                panic!(
                    "`data.len()` ({} bytes) overflows {}",
                    size,
                    core::any::type_name::<S>(),
                )
            }),
            data,
        }
    }
}

//--- Access to the inner data

impl<S, T: ?Sized> Deref for SizePrefixed<S, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<S, T: ?Sized> DerefMut for SizePrefixed<S, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<S, T: ?Sized> Borrow<T> for SizePrefixed<S, T> {
    fn borrow(&self) -> &T {
        &self.data
    }
}

impl<S, T: ?Sized> BorrowMut<T> for SizePrefixed<S, T> {
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<S, T: ?Sized> AsRef<T> for SizePrefixed<S, T> {
    fn as_ref(&self) -> &T {
        &self.data
    }
}

impl<S, T: ?Sized> AsMut<T> for SizePrefixed<S, T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

//--- Equality

impl<S, T: ?Sized + PartialEq> PartialEq for SizePrefixed<S, T> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<S, T: ?Sized + Eq> Eq for SizePrefixed<S, T> {}

//--- Ordering

impl<S, T: ?Sized + PartialOrd> PartialOrd for SizePrefixed<S, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.data.partial_cmp(&other.data)
    }
}

impl<S, T: ?Sized + Ord> Ord for SizePrefixed<S, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.cmp(&other.data)
    }
}

//--- Formatting

impl<S, T: ?Sized + fmt::Debug> fmt::Debug for SizePrefixed<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SizePrefixed").field(&&self.data).finish()
    }
}

//--- Parsing from DNS messages

impl<'b, S, T: ParseMessageBytes<'b>> ParseMessageBytes<'b>
    for SizePrefixed<S, T>
where
    S: SplitMessageBytes<'b> + TryFrom<usize> + Into<usize>,
{
    fn parse_message_bytes(
        contents: &'b [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        let (size, rest) = S::split_message_bytes(contents, start)?;
        if rest + size.into() != contents.len() {
            return Err(ParseError);
        }
        T::parse_message_bytes(contents, rest).map(Self::new)
    }
}

impl<'b, S, T: ParseMessageBytes<'b>> SplitMessageBytes<'b>
    for SizePrefixed<S, T>
where
    S: SplitMessageBytes<'b> + TryFrom<usize> + Into<usize>,
{
    fn split_message_bytes(
        contents: &'b [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let (size, rest) = S::split_message_bytes(contents, start)?;
        let (start, rest) = (rest, rest + size.into());
        let contents = contents.get(..rest).ok_or(ParseError)?;
        let data = T::parse_message_bytes(contents, start)?;
        Ok((Self::new(data), rest))
    }
}

//--- Parsing from bytes

impl<'b, S, T: ParseBytes<'b>> ParseBytes<'b> for SizePrefixed<S, T>
where
    S: SplitBytes<'b> + TryFrom<usize> + Into<usize>,
{
    fn parse_bytes(bytes: &'b [u8]) -> Result<Self, ParseError> {
        let (size, rest) = S::split_bytes(bytes)?;
        if rest.len() != size.into() {
            return Err(ParseError);
        }
        T::parse_bytes(bytes).map(Self::new)
    }
}

impl<'b, S, T: ParseBytes<'b>> SplitBytes<'b> for SizePrefixed<S, T>
where
    S: SplitBytes<'b> + TryFrom<usize> + Into<usize>,
{
    fn split_bytes(bytes: &'b [u8]) -> Result<(Self, &'b [u8]), ParseError> {
        let (size, rest) = S::split_bytes(bytes)?;
        let size: usize = size.into();
        // TODO(1.80): Use 'slice::split_at_checked()'.
        if rest.len() < size {
            return Err(ParseError);
        }
        let (data, rest) = rest.split_at(size);
        let data = T::parse_bytes(data)?;
        Ok((Self::new(data), rest))
    }
}

unsafe impl<S, T: ?Sized + ParseBytesZC> ParseBytesZC for SizePrefixed<S, T>
where
    S: SplitBytesZC + Copy + Into<usize>,
{
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        let addr = bytes.as_ptr();
        let (size, rest) = S::split_bytes_by_ref(bytes)?;
        if rest.len() != (*size).into() {
            return Err(ParseError);
        }
        let last = T::parse_bytes_by_ref(rest)?;
        let ptr = last.ptr_with_addr(addr as *const ());

        // SAFETY:
        //
        // - 'addr_of!((*(ptr as *const Self)).size) == size as *const S'.
        //   The 'size' field of 'ptr' is thus valid for reads for the
        //   lifetime of 'size', which is the same as the lifetime of 'bytes'.
        //
        // - 'addr_of!((*(ptr as *const Self)).data) == last as *const T'.
        //   The 'data' field of 'ptr' is thus valid for reads for the
        //   lifetime of 'last', which is the same as the lifetime of 'bytes'.
        //
        // - Thus, 'ptr' is valid for reads of 'Self' for the lifetime of
        //   'bytes'.
        Ok(unsafe { &*(ptr as *const Self) })
    }
}

unsafe impl<S, T: ?Sized + ParseBytesZC> SplitBytesZC for SizePrefixed<S, T>
where
    S: SplitBytesZC + Copy + Into<usize>,
{
    fn split_bytes_by_ref(bytes: &[u8]) -> Result<(&Self, &[u8]), ParseError> {
        let addr = bytes.as_ptr();
        let (&size, rest) = S::split_bytes_by_ref(bytes)?;
        if rest.len() < size.into() {
            return Err(ParseError);
        }
        let (data, rest) = rest.split_at(size.into());
        let last = T::parse_bytes_by_ref(data)?;
        let ptr = last.ptr_with_addr(addr as *const ());

        // SAFETY:
        //
        // - 'addr_of!((*(ptr as *const Self)).size) == size as *const S'.
        //   The 'size' field of 'ptr' is thus valid for reads for the
        //   lifetime of 'size', which is the same as the lifetime of 'bytes'.
        //
        // - 'addr_of!((*(ptr as *const Self)).data) == last as *const T'.
        //   The 'data' field of 'ptr' is thus valid for reads for the
        //   lifetime of 'last', which is the same as the lifetime of 'bytes'.
        //
        // - Thus, 'ptr' is valid for reads of 'Self' for the lifetime of
        //   'bytes'.
        Ok((unsafe { &*(ptr as *const Self) }, rest))
    }
}

//--- Building into DNS messages

impl<S, T: ?Sized + BuildIntoMessage> BuildIntoMessage for SizePrefixed<S, T>
where
    S: AsBytes + Default + TryFrom<usize>,
{
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> BuildResult {
        assert_eq!(builder.uncommitted(), &[] as &[u8]);
        let size_size = core::mem::size_of::<S>();
        builder.append_bytes(S::default().as_bytes())?;
        self.data.build_into_message(builder.delegate())?;
        let size = builder.uncommitted().len() - size_size;
        let size = S::try_from(size).unwrap_or_else(|_| {
            panic!(
                "`data.len()` ({} bytes) overflows {}",
                size,
                core::any::type_name::<S>(),
            )
        });

        // SAFETY:
        //
        // - 'S' was built using 'builder.append_bytes()', and so has not
        //   interacted with the name compressor.
        //
        // - It is sound to modify the built 'S', as this cannot break the
        //   name compression logic.
        let size_buf = unsafe { &mut builder.uncommitted_mut()[..size_size] };
        size_buf.copy_from_slice(size.as_bytes());

        Ok(builder.commit())
    }
}

//--- Building into byte strings

impl<S, T: ?Sized + BuildBytes> BuildBytes for SizePrefixed<S, T>
where
    S: AsBytes + Default + TryFrom<usize>,
{
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        // Get the size area to fill in afterwards.
        let size_size = core::mem::size_of::<S>();
        if bytes.len() < size_size {
            return Err(TruncationError);
        }
        let (size_buf, data_buf) = bytes.split_at_mut(size_size);
        let data_buf_len = data_buf.len();
        let rest = self.data.build_bytes(data_buf)?;
        let size = data_buf_len - rest.len();
        let size = S::try_from(size).unwrap_or_else(|_| {
            panic!(
                "`data.len()` ({} bytes) overflows {}",
                size,
                core::any::type_name::<S>(),
            )
        });
        size_buf.copy_from_slice(size.as_bytes());
        Ok(rest)
    }
}
