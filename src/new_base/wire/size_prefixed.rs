//! Working with (U16-)size-prefixed data.

use core::{
    borrow::{Borrow, BorrowMut},
    cmp::Ordering,
    fmt,
    ops::{Deref, DerefMut},
};

use domain_macros::UnsizedClone;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
};

use super::{
    AsBytes, BuildBytes, ParseBytes, ParseBytesByRef, ParseError, SplitBytes,
    SplitBytesByRef, TruncationError,
};

//----------- SizePrefixed ---------------------------------------------------

/// A wrapper adding a size prefix to a message.
///
/// This is a common element in DNS messages (e.g. for record data and EDNS
/// options).  When serialized as bytes, the inner value is prefixed with an
/// integer (often a [`U16`](super::U16)) indicating the length of the inner
/// value in bytes.
#[derive(Copy, Clone, AsBytes, UnsizedClone)]
#[repr(C)]
pub struct SizePrefixed<S, T: ?Sized> {
    /// The size prefix (needed for 'ParseBytesByRef' / 'AsBytes').
    ///
    /// This value is always consistent with the size of 'data' if it is
    /// (de)serialized in-place.  By the bounds on 'ParseBytesByRef' and
    /// 'AsBytes', the serialized size is the same as 'size_of_val(&data)'.
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
    /// Panics if the data size does not fit in `S`.
    pub fn new(data: T) -> Self {
        let size = core::mem::size_of::<T>();
        Self {
            size: S::try_from(size).unwrap_or_else(|_| {
                panic!("`data.len()` does not fit in the size field")
            }),
            data,
        }
    }
}

//--- Conversion from the inner data

impl<S, T> From<T> for SizePrefixed<S, T>
where
    S: TryFrom<usize>,
{
    fn from(value: T) -> Self {
        Self::new(value)
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
    S: SplitMessageBytes<'b> + TryFrom<usize> + TryInto<usize>,
{
    fn parse_message_bytes(
        contents: &'b [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        let (size, rest) = S::split_message_bytes(contents, start)?;
        let size = size.try_into().map_err(|_| ParseError)?;
        if rest + size != contents.len() {
            return Err(ParseError);
        }
        T::parse_message_bytes(contents, rest).map(Self::new)
    }
}

impl<'b, S, T: ParseMessageBytes<'b>> SplitMessageBytes<'b>
    for SizePrefixed<S, T>
where
    S: SplitMessageBytes<'b> + TryFrom<usize> + TryInto<usize>,
{
    fn split_message_bytes(
        contents: &'b [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let (size, rest) = S::split_message_bytes(contents, start)?;
        let size = size.try_into().map_err(|_| ParseError)?;
        let (start, rest) = (rest, rest + size);
        let contents = contents.get(..rest).ok_or(ParseError)?;
        let data = T::parse_message_bytes(contents, start)?;
        Ok((Self::new(data), rest))
    }
}

//--- Parsing from bytes

impl<'b, S, T: ParseBytes<'b>> ParseBytes<'b> for SizePrefixed<S, T>
where
    S: SplitBytes<'b> + TryFrom<usize> + TryInto<usize>,
{
    fn parse_bytes(bytes: &'b [u8]) -> Result<Self, ParseError> {
        let (size, rest) = S::split_bytes(bytes)?;
        let size = size.try_into().map_err(|_| ParseError)?;
        if rest.len() != size {
            return Err(ParseError);
        }
        T::parse_bytes(bytes).map(Self::new)
    }
}

impl<'b, S, T: ParseBytes<'b>> SplitBytes<'b> for SizePrefixed<S, T>
where
    S: SplitBytes<'b> + TryFrom<usize> + TryInto<usize>,
{
    fn split_bytes(bytes: &'b [u8]) -> Result<(Self, &'b [u8]), ParseError> {
        let (size, rest) = S::split_bytes(bytes)?;
        let size = size.try_into().map_err(|_| ParseError)?;
        if rest.len() < size {
            return Err(ParseError);
        }
        let (data, rest) = rest.split_at(size);
        let data = T::parse_bytes(data)?;
        Ok((Self::new(data), rest))
    }
}

unsafe impl<S, T: ?Sized + ParseBytesByRef> ParseBytesByRef
    for SizePrefixed<S, T>
where
    S: SplitBytesByRef + Copy + TryFrom<usize> + TryInto<usize>,
{
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        let addr = bytes.as_ptr();
        let (&size, rest) = S::split_bytes_by_ref(bytes)?;
        let size = size.try_into().map_err(|_| ParseError)?;
        if rest.len() != size {
            return Err(ParseError);
        }
        let last = T::parse_bytes_by_ref(rest)?;
        let ptr = last.ptr_with_address(addr as *const ());

        // SAFETY:
        // - 'bytes' is a 'U16' followed by a 'T'.
        // - 'T' is 'ParseBytesByRef' and so is unaligned.
        // - 'Self' is 'repr(C)' and so has no alignment or padding.
        // - The layout of 'Self' is identical to '(U16, T)'.
        Ok(unsafe { &*(ptr as *const Self) })
    }

    fn parse_bytes_by_mut(bytes: &mut [u8]) -> Result<&mut Self, ParseError> {
        let addr = bytes.as_ptr();
        let (&mut size, rest) = S::split_bytes_by_mut(bytes)?;
        let size = size.try_into().map_err(|_| ParseError)?;
        if rest.len() != size {
            return Err(ParseError);
        }
        let last = T::parse_bytes_by_mut(rest)?;
        let ptr = last.ptr_with_address(addr as *const ());

        // SAFETY:
        // - 'bytes' is a 'U16' followed by a 'T'.
        // - 'T' is 'ParseBytesByRef' and so is unaligned.
        // - 'Self' is 'repr(C)' and so has no alignment or padding.
        // - The layout of 'Self' is identical to '(U16, T)'.
        Ok(unsafe { &mut *(ptr as *const Self as *mut Self) })
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        self.data.ptr_with_address(addr) as *const Self
    }
}

unsafe impl<S, T: ?Sized + ParseBytesByRef> SplitBytesByRef
    for SizePrefixed<S, T>
where
    S: SplitBytesByRef + Copy + TryFrom<usize> + TryInto<usize>,
{
    fn split_bytes_by_ref(
        bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        let addr = bytes.as_ptr();
        let (&size, rest) = S::split_bytes_by_ref(bytes)?;
        let size = size.try_into().map_err(|_| ParseError)?;
        if rest.len() < size {
            return Err(ParseError);
        }
        let (data, rest) = rest.split_at(size);
        let last = T::parse_bytes_by_ref(data)?;
        let ptr = last.ptr_with_address(addr as *const ());

        // SAFETY:
        // - 'bytes' is a 'U16' followed by a 'T'.
        // - 'T' is 'ParseBytesByRef' and so is unaligned.
        // - 'Self' is 'repr(C)' and so has no alignment or padding.
        // - The layout of 'Self' is identical to '(U16, T)'.
        Ok((unsafe { &*(ptr as *const Self) }, rest))
    }

    fn split_bytes_by_mut(
        bytes: &mut [u8],
    ) -> Result<(&mut Self, &mut [u8]), ParseError> {
        let addr = bytes.as_ptr();
        let (&mut size, rest) = S::split_bytes_by_mut(bytes)?;
        let size = size.try_into().map_err(|_| ParseError)?;
        if rest.len() < size {
            return Err(ParseError);
        }
        let (data, rest) = rest.split_at_mut(size);
        let last = T::parse_bytes_by_mut(data)?;
        let ptr = last.ptr_with_address(addr as *const ());

        // SAFETY:
        // - 'bytes' is a 'U16' followed by a 'T'.
        // - 'T' is 'ParseBytesByRef' and so is unaligned.
        // - 'Self' is 'repr(C)' and so has no alignment or padding.
        // - The layout of 'Self' is identical to '(U16, T)'.
        Ok((unsafe { &mut *(ptr as *const Self as *mut Self) }, rest))
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
            panic!("`data.len()` does not fit in the size field")
        });
        // SAFETY: An 'S' is being modified, not a domain name.
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
            panic!("`data.len()` does not fit in the size field")
        });
        size_buf.copy_from_slice(size.as_bytes());
        Ok(rest)
    }
}
