//! Working with (U16-)size-prefixed data.

use core::{
    borrow::{Borrow, BorrowMut},
    ops::{Deref, DerefMut},
};

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseFromMessage, SplitFromMessage},
    Message,
};

use super::{
    AsBytes, BuildBytes, ParseBytes, ParseBytesByRef, ParseError, SplitBytes,
    SplitBytesByRef, TruncationError, U16,
};

//----------- SizePrefixed ---------------------------------------------------

/// A wrapper adding a 16-bit size prefix to a message.
///
/// This is a common element in DNS messages (e.g. for record data and EDNS
/// options).  When serialized as bytes, the inner value is prefixed with a
/// 16-bit network-endian integer indicating the length of the inner value in
/// bytes.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SizePrefixed<T: ?Sized> {
    /// The size prefix (needed for 'ParseBytesByRef' / 'AsBytes').
    ///
    /// This value is always consistent with the size of 'data' if it is
    /// (de)serialized in-place.  By the bounds on 'ParseBytesByRef' and
    /// 'AsBytes', the serialized size is the same as 'size_of_val(&data)'.
    size: U16,

    /// The inner data.
    data: T,
}

//--- Construction

impl<T> SizePrefixed<T> {
    const VALID_SIZE: () = assert!(core::mem::size_of::<T>() < 65536);

    /// Construct a [`SizePrefixed`].
    ///
    /// # Panics
    ///
    /// Panics if the data is 64KiB or more in size.
    pub const fn new(data: T) -> Self {
        // Force the 'VALID_SIZE' assertion to be evaluated.
        #[allow(clippy::let_unit_value)]
        let _ = Self::VALID_SIZE;

        Self {
            size: U16::new(core::mem::size_of::<T>() as u16),
            data,
        }
    }
}

//--- Conversion from the inner data

impl<T> From<T> for SizePrefixed<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

//--- Access to the inner data

impl<T: ?Sized> Deref for SizePrefixed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: ?Sized> DerefMut for SizePrefixed<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: ?Sized> Borrow<T> for SizePrefixed<T> {
    fn borrow(&self) -> &T {
        &self.data
    }
}

impl<T: ?Sized> BorrowMut<T> for SizePrefixed<T> {
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T: ?Sized> AsRef<T> for SizePrefixed<T> {
    fn as_ref(&self) -> &T {
        &self.data
    }
}

impl<T: ?Sized> AsMut<T> for SizePrefixed<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

//--- Parsing from DNS messages

impl<'b, T: ParseFromMessage<'b>> ParseFromMessage<'b> for SizePrefixed<T> {
    fn parse_from_message(
        message: &'b Message,
        start: usize,
    ) -> Result<Self, ParseError> {
        let (&size, rest) = <&U16>::split_from_message(message, start)?;
        if rest + size.get() as usize != message.contents.len() {
            return Err(ParseError);
        }
        T::parse_from_message(message, rest).map(Self::new)
    }
}

impl<'b, T: ParseFromMessage<'b>> SplitFromMessage<'b> for SizePrefixed<T> {
    fn split_from_message(
        message: &'b Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let (&size, rest) = <&U16>::split_from_message(message, start)?;
        let (start, rest) = (rest, rest + size.get() as usize);
        if rest > message.contents.len() {
            return Err(ParseError);
        }
        let message = message.slice_to(rest);
        let data = T::parse_from_message(message, start)?;
        Ok((Self::new(data), rest))
    }
}

//--- Parsing from bytes

impl<'b, T: ParseBytes<'b>> ParseBytes<'b> for SizePrefixed<T> {
    fn parse_bytes(bytes: &'b [u8]) -> Result<Self, ParseError> {
        let (size, rest) = U16::split_bytes(bytes)?;
        if rest.len() != size.get() as usize {
            return Err(ParseError);
        }
        T::parse_bytes(bytes).map(Self::new)
    }
}

impl<'b, T: ParseBytes<'b>> SplitBytes<'b> for SizePrefixed<T> {
    fn split_bytes(bytes: &'b [u8]) -> Result<(Self, &'b [u8]), ParseError> {
        let (size, rest) = U16::split_bytes(bytes)?;
        if rest.len() < size.get() as usize {
            return Err(ParseError);
        }
        let (data, rest) = rest.split_at(size.get() as usize);
        let data = T::parse_bytes(data)?;
        Ok((Self::new(data), rest))
    }
}

unsafe impl<T: ?Sized + ParseBytesByRef> ParseBytesByRef for SizePrefixed<T> {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        let addr = bytes.as_ptr();
        let (size, rest) = U16::split_bytes_by_ref(bytes)?;
        if rest.len() != size.get() as usize {
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
        let (size, rest) = U16::split_bytes_by_mut(bytes)?;
        if rest.len() != size.get() as usize {
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

unsafe impl<T: ?Sized + ParseBytesByRef> SplitBytesByRef for SizePrefixed<T> {
    fn split_bytes_by_ref(
        bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        let addr = bytes.as_ptr();
        let (size, rest) = U16::split_bytes_by_ref(bytes)?;
        if rest.len() < size.get() as usize {
            return Err(ParseError);
        }
        let (data, rest) = rest.split_at(size.get() as usize);
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
        let (size, rest) = U16::split_bytes_by_mut(bytes)?;
        if rest.len() < size.get() as usize {
            return Err(ParseError);
        }
        let (data, rest) = rest.split_at_mut(size.get() as usize);
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

impl<T: ?Sized + BuildIntoMessage> BuildIntoMessage for SizePrefixed<T> {
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> BuildResult {
        assert_eq!(builder.appended(), &[] as &[u8]);
        builder.append_bytes(&0u16.to_be_bytes())?;
        self.data.build_into_message(builder.delegate())?;
        let size = builder.appended().len() - 2;
        let size = u16::try_from(size).expect("the data never exceeds 64KiB");
        // SAFETY: A 'U16' is being modified, not a domain name.
        let size_buf = unsafe { &mut builder.appended_mut()[0..2] };
        size_buf.copy_from_slice(&size.to_be_bytes());
        Ok(builder.commit())
    }
}

//--- Building into byte strings

impl<T: ?Sized + BuildBytes> BuildBytes for SizePrefixed<T> {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        // Get the size area to fill in afterwards.
        let (size_buf, data_buf) =
            U16::split_bytes_by_mut(bytes).map_err(|_| TruncationError)?;
        let data_buf_len = data_buf.len();
        let rest = self.data.build_bytes(data_buf)?;
        let size = data_buf_len - rest.len();
        assert!(size < 65536, "Cannot serialize >=64KiB into 16-bit integer");
        *size_buf = U16::new(size as u16);
        Ok(rest)
    }
}

unsafe impl<T: ?Sized + AsBytes> AsBytes for SizePrefixed<T> {
    // For debugging, we check that the serialized size is correct.
    #[cfg(debug_assertions)]
    fn as_bytes(&self) -> &[u8] {
        let size: usize = self.size.get().into();
        assert_eq!(size, core::mem::size_of_val(&self.data));

        // SAFETY:
        // - 'Self' has no padding bytes and no interior mutability.
        // - Its size in memory is exactly 'size_of_val(self)'.
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of_val(self),
            )
        }
    }
}
