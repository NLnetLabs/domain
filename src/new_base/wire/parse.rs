//! Parsing bytes in the basic network format.

use core::fmt;
use core::mem::MaybeUninit;

//----------- ParseBytes -----------------------------------------------------

/// Parsing from a byte sequence.
pub trait ParseBytes<'a>: Sized {
    /// Parse a value of [`Self`] from the given byte sequence.
    ///
    /// The returned value may borrow from the byte sequence.  This allows it
    /// to avoid copying data unnecessarily.
    ///
    /// The entirety of the input must be used.  If some input bytes would be
    /// left over, [`ParseError`] should be returned.
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError>;
}

impl<'a> ParseBytes<'a> for u8 {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let [result] = bytes else {
            return Err(ParseError);
        };

        Ok(*result)
    }
}

impl<'a, T: ?Sized + ParseBytesByRef> ParseBytes<'a> for &'a T {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        T::parse_bytes_by_ref(bytes).map_err(|_| ParseError)
    }
}

impl<'a, T: SplitBytes<'a>, const N: usize> ParseBytes<'a> for [T; N] {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        match Self::split_bytes(bytes) {
            Ok((this, &[])) => Ok(this),
            _ => Err(ParseError),
        }
    }
}

#[cfg(feature = "std")]
impl<'a> ParseBytes<'a> for std::vec::Vec<u8> {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        Ok(bytes.to_vec())
    }
}

#[cfg(feature = "std")]
impl<'a> ParseBytes<'a> for std::string::String {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        str::parse_bytes_by_ref(bytes).map(std::string::String::from)
    }
}

/// Deriving [`ParseBytes`] automatically.
///
/// [`ParseBytes`] can be derived on `struct`s (not `enum`s or `union`s).  All
/// fields except the last must implement [`SplitBytes`], while the last field
/// only needs to implement [`ParseBytes`].
///
/// Here's a simple example:
///
/// ```
/// # use domain::new_base::wire::{ParseBytes, SplitBytes, U32, ParseError};
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(ParseBytes)':
/// impl<'bytes, T> ParseBytes<'bytes> for Foo<T>
/// where
///     U32: SplitBytes<'bytes>,
///     Bar<T>: ParseBytes<'bytes>,
/// {
///     fn parse_bytes(
///         bytes: &'bytes [u8],
///     ) -> Result<Self, ParseError> {
///         let (field_a, bytes) = U32::split_bytes(bytes)?;
///         let field_b = <Bar<T>>::parse_bytes(bytes)?;
///         Ok(Self { a: field_a, b: field_b })
///     }
/// }
/// ```
pub use domain_macros::ParseBytes;

//----------- SplitBytes -----------------------------------------------------

/// Parsing from the start of a byte sequence.
pub trait SplitBytes<'a>: Sized + ParseBytes<'a> {
    /// Parse a value of [`Self`] from the start of the byte sequence.
    ///
    /// If parsing is successful, the parsed value and the rest of the input
    /// (the part that was not parsed) are returned.  On failure, a
    /// [`ParseError`] is returned.
    ///
    /// ## Non-Greedy Parsing
    ///
    /// This function is _non-greedy_.  This can be interpreted in several
    /// equivalent ways:
    ///
    /// - If `split_bytes()` returns successfully for some input sequence, it
    ///   would return exactly the same `Self` value if more bytes were added
    ///   to the end of the input.
    ///
    /// - The unparsed part of the input (that is returned on success) does
    ///   not influence the function; those bytes are not examined.
    ///
    /// - `Self` has an intrinsic length to it; this may be a constant, or it
    ///   may be determined by examining the parsed part of the input (e.g.
    ///   for size-prefixed data).
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError>;
}

impl<'a> SplitBytes<'a> for u8 {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        bytes.split_first().map(|(&f, r)| (f, r)).ok_or(ParseError)
    }
}

impl<'a, T: ?Sized + SplitBytesByRef> SplitBytes<'a> for &'a T {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        T::split_bytes_by_ref(bytes).map_err(|_| ParseError)
    }
}

impl<'a, T: SplitBytes<'a>, const N: usize> SplitBytes<'a> for [T; N] {
    fn split_bytes(
        mut bytes: &'a [u8],
    ) -> Result<(Self, &'a [u8]), ParseError> {
        // TODO: Rewrite when either 'array_try_map' or 'try_array_from_fn'
        // is stabilized.

        /// A guard for dropping initialized elements on panic / failure.
        struct Guard<T, const N: usize> {
            buffer: [MaybeUninit<T>; N],
            initialized: usize,
        }

        impl<T, const N: usize> Drop for Guard<T, N> {
            fn drop(&mut self) {
                for elem in &mut self.buffer[..self.initialized] {
                    // SAFETY: The first 'initialized' elems are initialized.
                    unsafe { elem.assume_init_drop() };
                }
            }
        }

        let mut guard = Guard::<T, N> {
            buffer: [const { MaybeUninit::uninit() }; N],
            initialized: 0,
        };

        while guard.initialized < N {
            let (elem, rest) = T::split_bytes(bytes)?;
            guard.buffer[guard.initialized].write(elem);
            bytes = rest;
            guard.initialized += 1;
        }

        // Disable the guard since we're moving data out now.
        guard.initialized = 0;

        // SAFETY: '[MaybeUninit<T>; N]' and '[T; N]' have the same layout,
        // because 'MaybeUninit<T>' and 'T' have the same layout, because it
        // is documented in the standard library.
        Ok((unsafe { core::mem::transmute_copy(&guard.buffer) }, bytes))
    }
}

/// Deriving [`SplitBytes`] automatically.
///
/// [`SplitBytes`] can be derived on `struct`s (not `enum`s or `union`s).  All
/// fields must implement [`SplitBytes`].
///
/// Here's a simple example:
///
/// ```
/// # use domain::new_base::wire::{ParseBytes, SplitBytes, U32, ParseError};
/// #[derive(ParseBytes)]
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(SplitBytes)':
/// impl<'bytes, T> SplitBytes<'bytes> for Foo<T>
/// where
///     U32: SplitBytes<'bytes>,
///     Bar<T>: SplitBytes<'bytes>,
/// {
///     fn split_bytes(
///         bytes: &'bytes [u8],
///     ) -> Result<(Self, &'bytes [u8]), ParseError> {
///         let (field_a, bytes) = U32::split_bytes(bytes)?;
///         let (field_b, bytes) = <Bar<T>>::split_bytes(bytes)?;
///         Ok((Self { a: field_a, b: field_b }, bytes))
///     }
/// }
/// ```
pub use domain_macros::SplitBytes;

//----------- ParseBytesByRef ------------------------------------------------

/// Zero-copy parsing from a byte sequence.
///
/// # Safety
///
/// Every implementation of [`ParseBytesByRef`] must satisfy the invariants
/// documented on [`parse_bytes_by_ref()`] and [`ptr_with_address()`].  An
/// incorrect implementation is considered to cause undefined behaviour.
///
/// [`parse_bytes_by_ref()`]: Self::parse_bytes_by_ref()
/// [`ptr_with_address()`]: Self::ptr_with_address()
///
/// Implementing types must also have no alignment (i.e. a valid instance of
/// [`Self`] can occur at any address).  This eliminates the possibility of
/// padding bytes when [`Self`] is part of a larger aggregate type.
pub unsafe trait ParseBytesByRef {
    /// Interpret a byte sequence as an instance of [`Self`].
    ///
    /// The byte sequence will be validated and re-interpreted as a reference
    /// to [`Self`].  The whole byte sequence must be used.  If the input is
    /// not a valid instance of [`Self`], a [`ParseError`] is returned.
    ///
    /// ## Invariants
    ///
    /// For the statement `let this: &T = T::parse_bytes_by_ref(bytes)?;`,
    ///
    /// - `bytes.as_ptr() == this as *const T as *const u8`.
    /// - `bytes.len() == core::mem::size_of_val(this)`.
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError>;

    /// Interpret a byte sequence as an instance of [`Self`], mutably.
    ///
    /// The byte sequence will be validated and re-interpreted as a reference
    /// to [`Self`].  The whole byte sequence must be used.  If the input is
    /// not a valid instance of [`Self`], a [`ParseError`] is returned.
    ///
    /// ## Invariants
    ///
    /// For the statement `let this: &mut T = T::parse_bytes_by_mut(bytes)?;`,
    ///
    /// - `bytes.as_ptr() == this as *const T as *const u8`.
    /// - `bytes.len() == core::mem::size_of_val(this)`.
    fn parse_bytes_by_mut(bytes: &mut [u8]) -> Result<&mut Self, ParseError>;

    /// Change the address of a pointer to [`Self`].
    ///
    /// When [`Self`] is used as the last field in a type that also implements
    /// [`ParseBytesByRef`], it may be dynamically sized, and so a pointer (or
    /// reference) to it may include additional metadata.  This metadata is
    /// included verbatim in any reference/pointer to the containing type.
    ///
    /// When the containing type implements [`ParseBytesByRef`], it needs to
    /// construct a reference/pointer to itself, which includes this metadata.
    /// Rust does not currently offer a general way to extract this metadata
    /// or pair it with another address, so this function is necessary.  The
    /// caller can construct a reference to [`Self`], then change its address
    /// to point to the containing type, then cast that pointer to the right
    /// type.
    ///
    /// # Implementing
    ///
    /// Most users will derive [`ParseBytesByRef`] and so don't need to worry
    /// about this.  For manual implementations:
    ///
    /// In the future, an adequate default implementation for this function
    /// may be provided.  Until then, it should be implemented using one of
    /// the following expressions:
    ///
    /// ```text
    /// fn ptr_with_address(
    ///     &self,
    ///     addr: *const (),
    /// ) -> *const Self {
    ///     // If 'Self' is Sized:
    ///     addr.cast::<Self>()
    ///
    ///     // If 'Self' is an aggregate whose last field is 'last':
    ///     self.last.ptr_with_address(addr) as *const Self
    /// }
    /// ```
    ///
    /// # Invariants
    ///
    /// For the statement `let result = Self::ptr_with_address(ptr, addr);`:
    ///
    /// - `result as usize == addr as usize`.
    /// - `core::ptr::metadata(result) == core::ptr::metadata(ptr)`.
    fn ptr_with_address(&self, addr: *const ()) -> *const Self;
}

unsafe impl ParseBytesByRef for u8 {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        if let [result] = bytes {
            Ok(result)
        } else {
            Err(ParseError)
        }
    }

    fn parse_bytes_by_mut(bytes: &mut [u8]) -> Result<&mut Self, ParseError> {
        if let [result] = bytes {
            Ok(result)
        } else {
            Err(ParseError)
        }
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        addr.cast()
    }
}

unsafe impl ParseBytesByRef for [u8] {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        Ok(bytes)
    }

    fn parse_bytes_by_mut(bytes: &mut [u8]) -> Result<&mut Self, ParseError> {
        Ok(bytes)
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        core::ptr::slice_from_raw_parts(addr.cast(), self.len())
    }
}

unsafe impl ParseBytesByRef for str {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        core::str::from_utf8(bytes).map_err(|_| ParseError)
    }

    fn parse_bytes_by_mut(bytes: &mut [u8]) -> Result<&mut Self, ParseError> {
        core::str::from_utf8_mut(bytes).map_err(|_| ParseError)
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        // NOTE: The Rust Reference indicates that 'str' has the same layout
        // as '[u8]' [1].  This is also the most natural layout for it.  Since
        // there's no way to construct a '*const str' from raw parts, we will
        // just construct a raw slice and transmute it.
        //
        // [1]: https://doc.rust-lang.org/reference/type-layout.html#str-layout

        self.as_bytes().ptr_with_address(addr) as *const Self
    }
}

unsafe impl<T: SplitBytesByRef, const N: usize> ParseBytesByRef for [T; N] {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        let (this, rest) = Self::split_bytes_by_ref(bytes)?;
        if rest.is_empty() {
            Ok(this)
        } else {
            Err(ParseError)
        }
    }

    fn parse_bytes_by_mut(bytes: &mut [u8]) -> Result<&mut Self, ParseError> {
        let (this, rest) = Self::split_bytes_by_mut(bytes)?;
        if rest.is_empty() {
            Ok(this)
        } else {
            Err(ParseError)
        }
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        addr.cast()
    }
}

/// Deriving [`ParseBytesByRef`] automatically.
///
/// [`ParseBytesByRef`] can be derived on `struct`s (not `enum`s or `union`s),
/// where a fixed memory layout (`repr(C)` or `repr(transparent)`) is used.
/// All fields except the last must implement [`SplitBytesByRef`], while the
/// last field only needs to implement [`ParseBytesByRef`].
///
/// Here's a simple example:
///
/// ```
/// # use domain::new_base::wire::{ParseBytesByRef, SplitBytesByRef, U32, ParseError};
/// #[repr(C)]
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(ParseBytesByRef)':
/// unsafe impl<T> ParseBytesByRef for Foo<T>
/// where Bar<T>: ParseBytesByRef {
///     fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
///         let addr = bytes.as_ptr();
///         let (_, bytes) = U32::split_bytes_by_ref(bytes)?;
///         let last = <Bar<T>>::parse_bytes_by_ref(bytes)?;
///         let this = last.ptr_with_address(addr as *const ());
///         Ok(unsafe { &*(this as *const Self) })
///     }
///
///     fn parse_bytes_by_mut(
///         bytes: &mut [u8],
///     ) -> Result<&mut Self, ParseError> {
///         let addr = bytes.as_ptr();
///         let (_, bytes) = U32::split_bytes_by_ref(bytes)?;
///         let last = <Bar<T>>::parse_bytes_by_ref(bytes)?;
///         let this = last.ptr_with_address(addr as *const ());
///         Ok(unsafe { &mut *(this as *const Self as *mut Self) })
///     }
///
///     fn ptr_with_address(&self, addr: *const ()) -> *const Self {
///         self.b.ptr_with_address(addr) as *const Self
///     }
/// }
/// ```
pub use domain_macros::ParseBytesByRef;

//----------- SplitBytesByRef ------------------------------------------------

/// Zero-copy parsing from the start of a byte sequence.
///
/// This is an extension of [`ParseBytesByRef`] for types which can determine
/// their own length when parsing.  It is usually implemented by [`Sized`]
/// types (where the length is just the size of the type), although it can be
/// sometimes implemented by unsized types.
///
/// # Non-Greedy Parsing
///
/// This parsing functions provided by this trait are _non-greedy_.  This can
/// be interpreted in several equivalent ways:
///
/// - If `split_bytes_by_{ref,mut}()` returns successfully for some input
///   sequence, it would return exactly the same `Self` value if more bytes
///   were added to the end of the input.
///
/// - The unparsed part of the input (that is returned on success) does
///   not influence the function; those bytes are not examined.
///
/// - `Self` has an intrinsic length to it; this may be a constant, or it
///   may be determined by examining the parsed part of the input (e.g.
///   for size-prefixed data).
///
/// # Safety
///
/// Every implementation of [`SplitBytesByRef`] must satisfy the invariants
/// documented on [`split_bytes_by_ref()`].  An incorrect implementation is
/// considered to cause undefined behaviour.
///
/// [`split_bytes_by_ref()`]: Self::split_bytes_by_ref()
///
/// Note that [`ParseBytesByRef`], required by this trait, also has several
/// invariants that need to be considered with care.
pub unsafe trait SplitBytesByRef: ParseBytesByRef {
    /// Interpret a byte sequence as an instance of [`Self`], mutably.
    ///
    /// The byte sequence will be validated and re-interpreted as a reference
    /// to [`Self`].  The length of [`Self`] will be determined, possibly
    /// based on the contents (but not the length!) of the input, and the
    /// remaining bytes will be returned.  If the input does not begin with a
    /// valid instance of [`Self`], a [`ParseError`] is returned.
    ///
    /// ## Invariants
    ///
    /// For the statement `let (this, rest) = T::split_bytes_by_ref(bytes)?;`,
    ///
    /// - `bytes.as_ptr() == this as *const T as *const u8`.
    /// - `bytes.len() == core::mem::size_of_val(this) + rest.len()`.
    /// - `bytes.as_ptr().offset(size_of_val(this)) == rest.as_ptr()`.
    fn split_bytes_by_ref(bytes: &[u8])
        -> Result<(&Self, &[u8]), ParseError>;

    /// Interpret a byte sequence as an instance of [`Self`].
    ///
    /// The byte sequence will be validated and re-interpreted as a reference
    /// to [`Self`].  The length of [`Self`] will be determined, possibly
    /// based on the contents (but not the length!) of the input, and the
    /// remaining bytes will be returned.  If the input does not begin with a
    /// valid instance of [`Self`], a [`ParseError`] is returned.
    ///
    /// ## Invariants
    ///
    /// For the statement `let (this, rest) = T::split_bytes_by_mut(bytes)?;`,
    ///
    /// - `bytes.as_ptr() == this as *const T as *const u8`.
    /// - `bytes.len() == core::mem::size_of_val(this) + rest.len()`.
    /// - `bytes.as_ptr().offset(size_of_val(this)) == rest.as_ptr()`.
    fn split_bytes_by_mut(
        bytes: &mut [u8],
    ) -> Result<(&mut Self, &mut [u8]), ParseError>;
}

unsafe impl SplitBytesByRef for u8 {
    fn split_bytes_by_ref(
        bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        bytes.split_first().ok_or(ParseError)
    }

    fn split_bytes_by_mut(
        bytes: &mut [u8],
    ) -> Result<(&mut Self, &mut [u8]), ParseError> {
        bytes.split_first_mut().ok_or(ParseError)
    }
}

unsafe impl<T: SplitBytesByRef, const N: usize> SplitBytesByRef for [T; N] {
    fn split_bytes_by_ref(
        mut bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        let start = bytes.as_ptr();
        for _ in 0..N {
            (_, bytes) = T::split_bytes_by_ref(bytes)?;
        }

        // SAFETY:
        // - 'T::split_bytes_by_ref()' was called 'N' times on successive
        //   positions, thus the original 'bytes' starts with 'N' instances
        //   of 'T' (even if 'T' is a ZST and so all instances overlap).
        // - 'N' consecutive 'T's have the same layout as '[T; N]'.
        // - Thus it is safe to cast 'start' to '[T; N]'.
        // - The referenced data has the same lifetime as the output.
        Ok((unsafe { &*start.cast::<[T; N]>() }, bytes))
    }

    fn split_bytes_by_mut(
        mut bytes: &mut [u8],
    ) -> Result<(&mut Self, &mut [u8]), ParseError> {
        let start = bytes.as_mut_ptr();
        for _ in 0..N {
            (_, bytes) = T::split_bytes_by_mut(bytes)?;
        }

        // SAFETY:
        // - 'T::split_bytes_by_ref()' was called 'N' times on successive
        //   positions, thus the original 'bytes' starts with 'N' instances
        //   of 'T' (even if 'T' is a ZST and so all instances overlap).
        // - 'N' consecutive 'T's have the same layout as '[T; N]'.
        // - Thus it is safe to cast 'start' to '[T; N]'.
        // - The referenced data has the same lifetime as the output.
        Ok((unsafe { &mut *start.cast::<[T; N]>() }, bytes))
    }
}

/// Deriving [`SplitBytesByRef`] automatically.
///
/// [`SplitBytesByRef`] can be derived on `struct`s (not `enum`s or `union`s),
/// where a fixed memory layout (`repr(C)` or `repr(transparent)`) is used.
/// All fields must implement [`SplitBytesByRef`].
///
/// Here's a simple example:
///
/// ```
/// # use domain::new_base::wire::{ParseBytesByRef, SplitBytesByRef, U32, ParseError};
/// #[derive(ParseBytesByRef)]
/// #[repr(C)]
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(SplitBytesByRef)':
/// unsafe impl<T> SplitBytesByRef for Foo<T>
/// where Bar<T>: SplitBytesByRef {
///     fn split_bytes_by_ref(
///         bytes: &[u8],
///     ) -> Result<(&Self, &[u8]), ParseError> {
///         let addr = bytes.as_ptr();
///         let (_, bytes) = U32::split_bytes_by_ref(bytes)?;
///         let (last, bytes) = <Bar<T>>::split_bytes_by_ref(bytes)?;
///         let this = last.ptr_with_address(addr as *const ());
///         Ok((unsafe { &*(this as *const Self) }, bytes))
///     }
///
///     fn split_bytes_by_mut(
///         bytes: &mut [u8],
///     ) -> Result<(&mut Self, &mut [u8]), ParseError> {
///         let addr = bytes.as_ptr();
///         let (_, bytes) = U32::split_bytes_by_mut(bytes)?;
///         let (last, bytes) = <Bar<T>>::split_bytes_by_mut(bytes)?;
///         let this = last.ptr_with_address(addr as *const ());
///         Ok((unsafe { &mut *(this as *const Self as *mut Self) }, bytes))
///     }
/// }
/// ```
pub use domain_macros::SplitBytesByRef;

//----------- ParseError -----------------------------------------------------

/// A DNS message parsing error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ParseError;

//--- Formatting

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DNS data could not be parsed from the wire format")
    }
}
